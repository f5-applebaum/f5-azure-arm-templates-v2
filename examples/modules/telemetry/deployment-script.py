# Prepopulating F5Telemetry_ASM similar to how F5 Telemetry Streaming Extension populates it through 
# Data Souce:  Type = Ingestion API
# So workbook doesn't complain F5Telemetry_ASM doesn't exist
# https://docs.microsoft.com/en-us/rest/api/loganalytics/create-request
# Taken from example https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api#python-3-sample
# As using Azure ARM Script resource which uses Azure CLI container

# Usage: Pass RESOURCE_GROUP, WORKSPACE_NAME and CUSTOMER_ID as ENV vars 

import os
import sys
import json
import requests
import datetime
import hashlib
import hmac
import base64
from optparse import OptionParser
from azure.cli.core import get_default_cli
import tempfile
import logging
FORMATTER = logging.Formatter("%(asctime)s — %(name)s — %(levelname)s — %(message)s")


#####################
######Functions######  
#####################

def get_console_handler():
   console_handler = logging.StreamHandler(sys.stdout)
   console_handler.setFormatter(FORMATTER)
   return console_handler

# Build the API signature
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")  
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization

# Build and send a request to the POST API
def post_data(customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        logger.info('SUCCESS: Log Message Accepted to API Ingestion Datasource')
        return 0
    else:
        logger.error("Response Code: {}".format(response.status_code))
        return 1

def az_cli (args_str):
    # TypeError: a bytes-like object is required, not 'str'
    # Open file in non-byte mode as knack complains
    temp = tempfile.TemporaryFile(mode='w+')
    args = args_str.split()
    code = get_default_cli().invoke(args , None, temp)
    temp.seek(0)
    data = temp.read().strip()
    temp.close()
    return [code, data]    

def main():

    parser = OptionParser()
    parser.add_option("-g", "--resource_group", action="store", type="string", dest="resource_group", help="resource_group ex. myAzureResourceGroup" )
    parser.add_option("-w", "--workspace_name", action="store", type="string", dest="workspace_name", help="Workspace Name. ex. f5telemetry" )
    parser.add_option("-i", "--customer_id", action="store", type="string", dest="customer_id", help="Workspace ID. ex. 2a27786d-60ce-45de-b5ba-06b605fdXXXXX" )
    parser.add_option("-k", "--shared_key", action="store", type="string", dest="shared_key", help="Primary Shared Key ex. H7UcHMuW8SLQ8gYJQpJ7xuFBXTZy1nnNjkBoWTleJcoTtcsllH/Ld5hrSNYxY81XRX" )
    parser.add_option("-t", "--log_type", action="store", type="string", dest="log_type", help="Azure Log Type ex. F5Telemetry_ASM" )
    parser.add_option("-l", "--script_log_level", action="store", type="string", dest="script_log_level", default=False, help="Script Logging Level. ex. INFO, DEBUG" )

    (options, args) = parser.parse_args()
    e = dict(os.environ.items())

    logger = logging.getLogger()
    logger.addHandler(get_console_handler())

    if options.script_log_level:
        script_log_level = options.script_log_level
        logger.setLevel(script_log_level.upper())
    elif 'SCRIPT_LOG_LEVEL' in e:
        script_log_level = e['LOG_LEVEL']
        logger.setLevel(script_log_level.upper())
    else: 
        logger.setLevel(logging.INFO)

    if options.resource_group:
        resource_group = options.resource_group
    elif 'RESOURCE_GROUP' in e:
        resource_group = e['RESOURCE_GROUP']
    else: 
        logger.error("resource_group key not found")

    if options.workspace_name:
        workspace_name = options.workspace_name
    elif 'WORKSPACE_NAME' in e:
        workspace_name = e['WORKSPACE_NAME']
    else: 
        logger.error("workspace_name key not found")

    if options.customer_id:
        customer_id = options.customer_id
    elif 'CUSTOMER_ID' in e:
        customer_id = e['CUSTOMER_ID']
    else: 
        logger.error("customer_id key not found")

    if options.log_type:
        log_type = options.log_type
    elif 'LOG_TYPE' in e:
        log_type = e['LOG_TYPE']
    else:
        log_type="F5Telemetry_ASM"

    if options.shared_key:
        shared_key = options.shared_key
    elif 'SHARED_KEY' in e:
        shared_key = e['SHARED_KEY']
    else:
        # ARM Template doesn't seem to have property to retrieve the Shared Keys
        logger.info("Workspace Shared Key Not Passed, obtaining via az cli command: ")
        command = f"monitor log-analytics workspace get-shared-keys --resource-group {resource_group} --workspace-name {workspace_name}"
        logger.info(command)
        code, response = az_cli( command )
        if 'primarySharedKey' in response:
            logger.info("Workspace Shared Keys found")
            response_json = json.loads(response)
            shared_key = response_json['primarySharedKey']
        else:
            logger.debug("code: %s" % (code))
            logger.debug("keys: %s" % (response))
            logger.error("Exiting. Workspace Shared Key NOT found. Check Deployment Script's userAssignedIdentity permissions to access the Workspace.")
            sys.exit(1)

    # An example JSON web monitor object
    json_data = [{
	    "hostname": "",
	    "management_ip_address": "",
	    "management_ip_address_2": "",
	    "http_class_name": "",
	    "web_application_name": "",
	    "policy_name": "",
	    "policy_apply_date": "",
	    "violations": "",
	    "support_id": "",
	    "request_status": "",
	    "response_code": "",
	    "ip_client": "",
	    "route_domain": "",
	    "method": "",
	    "protocol": "",
	    "query_string": "",
	    "x_forwarded_for_header_value": "",
	    "sig_ids": "",
	    "sig_names": "",
	    "date_time": "",
	    "severity": "",
	    "attack_type": "",
	    "geo_location": "",
	    "ip_address_intelligence": "",
	    "username": "",
	    "session_id": "",
	    "src_port": "",
	    "dest_port": "",
	    "dest_ip": "",
	    "sub_violations": "",
	    "virus_name": "",
	    "violation_rating": "",
	    "websocket_direction": "",
	    "websocket_message_type": "",
	    "device_id": "",
	    "staged_sig_ids": "",
	    "staged_sig_names": "",
	    "threat_campaign_names": "",
	    "staged_threat_campaign_names": "",
	    "blocking_exception_reason": "",
	    "captcha_result": "",
	    "microservice": "",
	    "tap_event_id": "",
	    "tap_vid": "",
	    "vs_name": "",
	    "sig_cves": "",
	    "staged_sig_cves": "",
	    "uri": "",
	    "fragment": "",
	    "request": "",
	    "response": "",
	    "telemetryEventCategory": "",
	    "application": "",
	    "f5tenant": ""
	}]
    body = json.dumps(json_data)

    post_data(customer_id, shared_key, body, log_type)

if __name__ == "__main__":
    main()