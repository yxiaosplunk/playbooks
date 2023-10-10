"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filtered_data' block
    filtered_data(container=container)
    # call 'filter_2' block
    filter_2(container=container)
    # call 'filter_3' block
    filter_3(container=container)

    return

@phantom.playbook_block()
def filtered_data(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filtered_data() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["URL Artifact", "in", "artifact:*.name"]
        ],
        name="filtered_data:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        url_reputation_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["url_reputation_1:action_result.summary.positives", ">", 3]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        join_format_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def join_format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_format_1() called")

    if phantom.completed(action_names=["url_reputation_2", "extract_ioc_1", "ip_reputation_1"]):
        # call connected block "format_1"
        format_1(container=container, handle=handle)

    return


@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_1() called")

    template = """Reputation summary for URL {0}\n\n---Overall Scores---\nVirusTotal Score:{1}\nVirusTotal Amount of Scans:{2}\n\nReputation summary for Email Received from {3}\n\n---Overall Scores---\nIPs: {4}\nVirusTotal Detected URLs: {5}\nVirusTotal Score: {6}"""

    # parameter list for template variable replacement
    parameters = [
        "url_reputation_1:action_result.parameter.url",
        "url_reputation_1:action_result.summary.positives",
        "url_reputation_1:action_result.summary.total_scans",
        "checkfromname:custom_function:senderemailaddress",
        "ip_reputation_1:action_result.parameter.ip",
        "ip_reputation_1:action_result.summary.detected_urls",
        "ip_reputation_1:action_result.data.*.detected_urls.*.positives"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    send_email_1(container=container)

    return


@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["Email Artifact", "in", "artifact:*.name"]
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        checkfromname(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def checkfromname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("checkfromname() called")
    import re

    filtered_artifact_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:artifact:*.cef.fromEmail"])

    filtered_artifact_0__cef_fromemail = [item[0] for item in filtered_artifact_0_data_filter_2]

    checkfromname__senderemailaddress = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    compile_obj = re.compile(r'[\w\.-]+@[\w\.-]+')
    extracted_email= compile_obj.search(filtered_artifact_0__cef_fromemail[0])
    
    checkfromname__senderemailaddress = extracted_email.group(0)
    phantom.debug("Extracted Sender Email Address: {}".format(checkfromname__senderemailaddress))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="checkfromname:senderemailaddress", value=json.dumps(checkfromname__senderemailaddress))

    return

@phantom.playbook_block()
def extract_ioc_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("extract_ioc_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    id_value = container.get("id", None)
    filtered_artifact_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:artifact:*.cef.emailHeaders.Received","filtered-data:filter_2:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'extract_ioc_1' call
    for filtered_artifact_0_item_filter_2 in filtered_artifact_0_data_filter_2:
        parameters.append({
            "text": filtered_artifact_0_item_filter_2[0],
            "severity": "medium",
            "file_type": "txt",
            "container_id": id_value,
            "parse_domains": True,
            "run_automation": True,
            "remap_cef_fields": "Do not apply CEF -> CIM remapping, only apply custom remap",
            "custom_remap_json": "{}",
            "context": {'artifact_id': filtered_artifact_0_item_filter_2[1]},
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("extract ioc", parameters=parameters, name="extract_ioc_1", assets=["parser"], callback=join_format_1)

    return


@phantom.playbook_block()
def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_3() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["IP Artifact", "in", "artifact:*.name"]
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        ip_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["ip_reputation_1:action_result.data.*.detected_urls.*.positives", ">", 0]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        join_format_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("send_email_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_1 = phantom.get_format_data(name="format_1")

    parameters = []

    if format_1 is not None:
        parameters.append({
            "to": "yxiao@splunk.com",
            "body": format_1,
            "from": "customer-support-soar@splunk.com",
            "subject": "Phantom Exercise 7",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="send_email_1", assets=["smtp"])

    return


@phantom.playbook_block()
def url_reputation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("url_reputation_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceDnsDomain","artifact:*.id"])

    parameters = []

    # build parameters list for 'url_reputation_2' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "url": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("url reputation", parameters=parameters, name="url_reputation_2", assets=["virustotal3"], callback=decision_1)

    return


@phantom.playbook_block()
def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("ip_reputation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'ip_reputation_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("ip reputation", parameters=parameters, name="ip_reputation_1", assets=["virustotal3"], callback=decision_2)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return