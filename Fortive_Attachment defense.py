"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'attachment_defense_description_1' block
    attachment_defense_description_1(container=container)

    return

@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_1() called")

    file_reputation_1_result_data = phantom.collect2(container=container, datapath=["file_reputation_1:action_result.summary","file_reputation_1:action_result.parameter.context.artifact_id"], action_results=results)
    ip_reputation_1_result_data = phantom.collect2(container=container, datapath=["ip_reputation_1:action_result.summary","ip_reputation_1:action_result.parameter.context.artifact_id"], action_results=results)

    file_reputation_1_result_item_0 = [item[0] for item in file_reputation_1_result_data]
    ip_reputation_1_result_item_0 = [item[0] for item in ip_reputation_1_result_data]

    parameters = []

    parameters.append({
        "input_1": file_reputation_1_result_item_0,
        "input_2": ip_reputation_1_result_item_0,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_1")

    return


@phantom.playbook_block()
def file_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("file_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.Threat_MD5_hash","artifact:*.id"])

    parameters = []

    # build parameters list for 'file_reputation' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "hash": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("file reputation", parameters=parameters, name="file_reputation", assets=["recorded_future"], callback=join_add_work_note_2)

    return


@phantom.playbook_block()
def ip_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("ip_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.senderIP","artifact:*.id"])

    parameters = []

    # build parameters list for 'ip_reputation' call
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

    phantom.act("ip reputation", parameters=parameters, name="ip_reputation", assets=["recorded_future"], callback=join_add_work_note_2)

    return


@phantom.playbook_block()
def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("send_email_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    sender_and_recipient_address_user_validation_result_data = phantom.collect2(container=container, datapath=["sender_and_recipient_address_user_validation:action_result.parameter.message","sender_and_recipient_address_user_validation:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'send_email_1' call
    for sender_and_recipient_address_user_validation_result_item in sender_and_recipient_address_user_validation_result_data:
        if sender_and_recipient_address_user_validation_result_item[0] is not None:
            parameters.append({
                "cc": "samir.shah@fortive.com",
                "to": "sabarirajan.thangavel@ftvitservices.com",
                "body": sender_and_recipient_address_user_validation_result_item[0],
                "from": "no-reply@fortive.com",
                "subject": "Test:Attachment_Defense-Alert",
                "context": {'artifact_id': sender_and_recipient_address_user_validation_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="send_email_1", assets=["smtp_fqdn"])

    return


@phantom.playbook_block()
def sender_and_recipient_address_user_validation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("sender_and_recipient_address_user_validation() called")

    # set user and message variables for phantom.prompt call

    user = "sabarirajan.thangavel@ftvitservices.com"
    role = None
    message = """Hi SOC Team,\n\nPlease validate if any business communication between Sender and Recipient in Proofpoint. \n\nSender address:{0}\nRecipient address:{1}\n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sender",
        "artifact:*.cef.Recipient"
    ]

    # responses
    response_types = [
        {
            "prompt": "Validate Sender address  is a legit?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        },
        {
            "prompt": "Validate Recipient address  is a legit?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=15, name="sender_and_recipient_address_user_validation", parameters=parameters, response_types=response_types, callback=risk_score_ip_address_and_file_reputation)

    return


@phantom.playbook_block()
def attachment_defense_description_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("attachment_defense_description_1() called")

    template = """Hi SOC Team,\n\nThis is a attachment defense Test alert triggered from SOAR.\n\nPlease take appropriate action on it:\n\ncontainer_id: {0}\n\ncreate_time:{1}\n\neventType:{2}\n\nsender:{3}\n\nRecipient:{4}\n\nThreat_Infomap_Classification:{5}\n\nSubject:{6}\n\nSenderIP:{7}\n\nThreat_MD5_hash:{8}\n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.id",
        "artifact:*.create_time",
        "artifact:*.cef.eventType",
        "artifact:*.cef.sender",
        "artifact:*.cef.Recipient",
        "artifact:*.cef.Threat_Infomap_Classification",
        "artifact:*.cef.subject",
        "artifact:*.cef.senderIP",
        "artifact:*.cef.Threat_MD5_hash"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="attachment_defense_description_1")

    create_sir_ticket(container=container)

    return


@phantom.playbook_block()
def create_sir_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_sir_ticket() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    attachment_defense_description_1 = phantom.get_format_data(name="attachment_defense_description_1")

    parameters = []

    parameters.append({
        "table": "sn_si_incident_import",
        "fields": "",
        "description": attachment_defense_description_1,
        "short_description": "Test:Attachment_Defense_Alert:SOAR Testing",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("create ticket", parameters=parameters, name="create_sir_ticket", assets=["servicenowprod"], callback=create_sir_ticket_callback)

    return


@phantom.playbook_block()
def create_sir_ticket_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_sir_ticket_callback() called")

    
    ip_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    file_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def risk_score_ip_address_and_file_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("risk_score_ip_address_and_file_reputation() called")

    template = """Hi Team,\n\nPlease find the risk score for IP address and File reputation hash values from recorded future.\n\nfile_reputation Risk_Score:{0}\n\nip_reputation Risk_Score:{1}\n\nValidate Sender address  is a legit?: {2}\n\nValidate Recipient address  is a legit?:  {3}\n"""

    # parameter list for template variable replacement
    parameters = [
        "file_reputation:action_result.summary",
        "ip_reputation:action_result.summary",
        "sender_and_recipient_address_user_validation:action_result.summary.responses.0",
        "sender_and_recipient_address_user_validation:action_result.summary.responses.1"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="risk_score_ip_address_and_file_reputation")

    worknote_update(container=container)

    return


@phantom.playbook_block()
def worknote_update(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("worknote_update() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    work_note_formatted_string = phantom.format(
        container=container,
        template="""Please find the business communication information for sender and Recipient address from the SOC Team validation. \n\nNote: a)If it's Yes(There is a Business Communication and it's a legit)\nb) If it's No (There is no Business Communication). \n\n\nValidate Sender address  is a legit?: {0}\n\nValidate Recipient address  is a legit?:{1}\n\nopco:{2}\n""",
        parameters=[
            "sender_and_recipient_address_user_validation:action_result.summary.responses.0",
            "sender_and_recipient_address_user_validation:action_result.summary.responses.1",
            "artifact:*.cef.opco"
        ])

    create_sir_ticket_result_data = phantom.collect2(container=container, datapath=["create_sir_ticket:action_result.data.*.sys_target_sys_id.value","create_sir_ticket:action_result.parameter.context.artifact_id"], action_results=results)
    sender_and_recipient_address_user_validation_result_data = phantom.collect2(container=container, datapath=["sender_and_recipient_address_user_validation:action_result.summary.responses.0","sender_and_recipient_address_user_validation:action_result.summary.responses.1","sender_and_recipient_address_user_validation:action_result.parameter.context.artifact_id"], action_results=results)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.opco","artifact:*.id"])

    parameters = []

    # build parameters list for 'worknote_update' call
    for create_sir_ticket_result_item in create_sir_ticket_result_data:
        for sender_and_recipient_address_user_validation_result_item in sender_and_recipient_address_user_validation_result_data:
            for container_artifact_item in container_artifact_data:
                if create_sir_ticket_result_item[0] is not None and work_note_formatted_string is not None:
                    parameters.append({
                        "id": create_sir_ticket_result_item[0],
                        "is_sys_id": True,
                        "work_note": work_note_formatted_string,
                        "table_name": "sn_si_incident",
                        "context": {'artifact_id': container_artifact_item[1]},
                    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add work note", parameters=parameters, name="worknote_update", assets=["servicenowprod"], callback=playbook_fortive__cb_block_hash_v2_copy_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["ip_reputation:action_result.status", "!=", None],
            ["file_reputation:action_result.status", "!=", None]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        sender_and_recipient_address_user_validation(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def join_add_work_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_add_work_note_2() called")

    if phantom.completed(action_names=["file_reputation", "ip_reputation"]):
        # call connected block "add_work_note_2"
        add_work_note_2(container=container, handle=handle)

    return


@phantom.playbook_block()
def add_work_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_work_note_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    work_note_formatted_string = phantom.format(
        container=container,
        template="""Hi SOC Team,\n\nIP & Hash Reputation checks are done through RF automation and below are the details. Please look into it,\n\nThreat_MD5_hash:{0}\n\nHash Reputation Checks in RF:{1}\n\nSender IP:{2}\n\nSender IP Reputation Checks in RF:{3}\n\nThanks,\nSOAR Automation Team.\n""",
        parameters=[
            "artifact:*.cef.Threat_MD5_hash",
            "file_reputation:action_result.summary",
            "artifact:*.cef.senderIP",
            "ip_reputation:action_result.summary"
        ])

    create_sir_ticket_result_data = phantom.collect2(container=container, datapath=["create_sir_ticket:action_result.data.*.sys_target_sys_id.value","create_sir_ticket:action_result.parameter.context.artifact_id"], action_results=results)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.Threat_MD5_hash","artifact:*.cef.senderIP","artifact:*.id"])
    file_reputation_result_data = phantom.collect2(container=container, datapath=["file_reputation:action_result.summary","file_reputation:action_result.parameter.context.artifact_id"], action_results=results)
    ip_reputation_result_data = phantom.collect2(container=container, datapath=["ip_reputation:action_result.summary","ip_reputation:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_work_note_2' call
    for create_sir_ticket_result_item in create_sir_ticket_result_data:
        for container_artifact_item in container_artifact_data:
            for file_reputation_result_item in file_reputation_result_data:
                for ip_reputation_result_item in ip_reputation_result_data:
                    if create_sir_ticket_result_item[0] is not None and work_note_formatted_string is not None:
                        parameters.append({
                            "id": create_sir_ticket_result_item[0],
                            "is_sys_id": True,
                            "work_note": work_note_formatted_string,
                            "table_name": "sn_si_incident",
                            "context": {'artifact_id': ip_reputation_result_item[1]},
                        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add work note", parameters=parameters, name="add_work_note_2", assets=["servicenowprod"], callback=decision_1)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["sender_and_recipient_address_user_validation:action_result.summary.responses.0", "==", "No"],
            ["sender_and_recipient_address_user_validation:action_result.summary.responses.1", "==", "No"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        return

    return


@phantom.playbook_block()
def get_opco_details(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_opco_details() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.opco"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    get_opco_details__header_out = None
    get_opco_details__url_out = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here... 
    opco= container_artifact_cef_item_0[0]

    opcos = {
        'acr': {'header':"'HYK6LYHLNHSETU7Z67PSS1CA/SM7V4WRVIF'",'url':"'https://defense-prod05.conferdeploy.net/appservices/v6/orgs/795FW934/reputations/overrides'"},
        'asp': {'header':"'I77WZ7USB22TZ978VA19HC12/L7YBFC3H6E'",'url':"'https://defense-prod05.conferdeploy.net/appservices/v6/orgs/N33FQW65/reputations/overrides'"},
        'cen': {'header':"'ZR6L53ZJCE4DTAQ5ZRNEVYZF/S3IQT7EI39'",'url':"'https://defense-prod05.conferdeploy.net/appservices/v6/orgs/76DF3JW7/reputations/overrides'"},
        'frs': {'header':"'UV3DH81SI3LRN3BSBUNJPRZV/RG359VB9KQ'",'url':"'https://defense-prod05.conferdeploy.net/appservices/v6/orgs/N88FDK85/reputations/overrides'"},
        'tm':  {'header':"'WP6K9RL49QWHBM2ZJSZ3U8S5/5ECMIRGMII'",'url':"'https://defense-prod05.conferdeploy.net/appservices/v6/orgs/N2MFYJ2Z/reputations/overrides'"},
        'ftv': {'header':"'WZ17RLJSDRINND3VU2RCIJ37/B6ZWJJDZ1N'",'url':"'https://defense-prod05.conferdeploy.net/appservices/v6/orgs/N5DFVQ2Z/reputations/overrides'"},
        'gor': {'header':"'K8741KZESG34K58HMVM1IBYI/RFJ6KI9Z4S'",'url':"'https://defense-prod05.conferdeploy.net/appservices/v6/orgs/NKZFRP6W/reputations/overrides'"},
        'isc': {'header':"'G92CFQ2WBZIUFWSZFFZFR7T1/QCDUICWKKJ'",'url':"'https://defense-prod05.conferdeploy.net/appservices/v6/orgs/7L9FE36N/reputations/overrides'"},
        'inv': {'header':"'2SNS9AIABEZ3DWP2A46VZPYN/V2WGZQ3F1C'",'url':"'https://defense-prod05.conferdeploy.net/appservices/v6/orgs/NJZFD8ZX/reputations/overrides'"},
        'jan': {'header':"'DYZ7S3AKJTYURFKB6LGJJMS1/CFZGRFJRN6'",'url':"'https://defense-prod05.conferdeploy.net/appservices/v6/orgs/76DFRPV2/reputations/overrides'"},
        'ldr': {'header':"'LDNKAWAR3Z1LLTEK9BVU1NZQ/3Z2619WN6C'",'url':"'https://defense-prod05.conferdeploy.net/appservices/v6/orgs/7P9F3VEV/reputations/overrides'"},
        'pse': {'header':"'R1NFRZJ3UWBGNR62WPFZ44I9/L87K9LHY8Q'",'url':"'https://defense-prod05.conferdeploy.net/appservices/v6/orgs/N4LFP44N/reputations/overrides'"},
        'qtc': {'header':"'7C3HIJEMKSMR8DDUZ498ICHN/CHZW3Z5JJA'",'url':"'https://defense-prod05.conferdeploy.net/appservices/v6/orgs/N4LFY6J3/reputations/overrides'"},
        'sg':  {'header':"'4URN17WSHMZ15EZ3IU6EAK7Z/QZY547AEI5'",'url':"'https://defense-prod05.conferdeploy.net/appservices/v6/orgs/7RZFW8XX/reputations/overrides'"},
        'svc': {'header':"'BSAB9C5ZEKR24I2FKGNB6ZAZ/JIS3ED89GB'",'url':"'https://defense-prod05.conferdeploy.net/appservices/v6/orgs/7Z2F2V22/reputations/overrides'"}
    }

    def switch(opco):
        header=opcos[opco]['header']
        url=opcos[opco]['url']
        return header, url
    header, url = switch(opco)

    get_opco_details__header_out=header
    get_opco_details__url_out=url

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="get_opco_details:header_out", value=json.dumps(get_opco_details__header_out))
    phantom.save_run_data(key="get_opco_details:url_out", value=json.dumps(get_opco_details__url_out))

    block_hash_custom_function(container=container)

    return


@phantom.playbook_block()
def block_hash_custom_function(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("block_hash_custom_function() called")
    import json
    import phantom.requests
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.Threat_MD5_hash"])
    get_opco_details__header_out = json.loads(phantom.get_run_data(key="get_opco_details:header_out"))
    get_opco_details__url_out = json.loads(phantom.get_run_data(key="get_opco_details:url_out"))

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    container_artifact_cef_item_1 = [item[1] for item in container_artifact_data]

    block_hash_custom_function__api_call_return = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    Threat_MD5_hash=None
    Threat_MD5_hash = container_artifact_cef_item_0[0]
    file_name=container_artifact_cef_item_1[0]
    get_opco_details__header_out=get_opco_details__header_out.strip("'")    
    headers1 = {"X-Auth-Token" : get_opco_details__header_out, "content-type": "application/json"}   
    
    url=get_opco_details__url_out.strip("'")    
    myobj = {"description": "An blacklist override for a sha256 hash","override_list": "BLACK_LIST","override_type": "SHA256","sha256_hash": Threat_MD5_hash, "filename": file_name}
    x = phantom.requests.post(url, data = json.dumps(myobj), headers=headers1)    
    block_hash_custom_function__api_call_return = x.json()

    ################################################################################
    ## Custom Code End
    
    ################################################################################
    phantom.save_run_data(key="block_hash_custom_function:api_call_return", value=json.dumps(block_hash_custom_function__api_call_return))

    result_summary(container=container)
    
    return

@phantom.playbook_block()
def result_summary(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("result_summary() called")

    template = """Hash value has been added to opco: {0}\nAdded SHA256 hash value to banned list/blacklist: {1}\nJSON response received {2}\n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.opco",
        "artifact:*.cef.Threat_MD5_hash",
        "block_hash_custom_function:custom_function:api_call_return"
    ]
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="result_summary")

    return

@phantom.playbook_block()
def playbook_fortive__cb_block_hash_v2_copy_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_fortive__cb_block_hash_v2_copy_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Fortive: CB_Block_Hash_v2_copy", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Fortive: CB_Block_Hash_v2_copy", container=container)

    debug_1(container=container)

    return


@phantom.playbook_block()
def hashout_url_out(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("hashout_url_out() called")

    template = """Hi Team,\nPlease find the below details\n\nheader_out:{0}\nurl_out:{1}\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook:launching_user.header_out",
        "playbook:launching_user.url_out"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="hashout_url_out")

    send_email_2(container=container)

    return


@phantom.playbook_block()
def send_email_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("send_email_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    hashout_url_out = phantom.get_format_data(name="hashout_url_out")

    parameters = []

    if hashout_url_out is not None:
        parameters.append({
            "from": "no-reply@fortive.com",
            "to": "sabarirajan.thangavel@ftvitservices.com",
            "subject": "hash_out and URL_Out value",
            "body": hashout_url_out,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="send_email_2", assets=["smtp_fqdn"])

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