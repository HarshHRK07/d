from mitmproxy import http, ctx
import re
import json
import os
from datetime import datetime

# Precompiled regex patterns
REGEX_PATTERNS = [
    re.compile(rb"payment_method_data\[card\]\[cvc\]=[\d]{3,4}"),
    re.compile(rb"card\[cvc\]=[\d]{3,4}"),
    re.compile(rb"source_data\[card\]\[cvc\]=[\d]{3,4}"),
    re.compile(rb"encryptedSecurityCode\":\s*\"[^\"]+\""),
    re.compile(rb"\"cvv\":\s*\"[\d]{3,4}\""),
    re.compile(rb"cc_cscv=[\d]{3,4}"),
    re.compile(rb"card\[cvv\]=[\d]{3,4}"),
    re.compile(rb"card\[cvv2\]=[\d]{3,4}"),
    re.compile(rb"security_code=[\d]{3,4}"),
    re.compile(rb"securityCode=[\d]{3,4}"),
    re.compile(rb"cvvNumber=[\d]{3,4}"),
    re.compile(rb"card_verification_value=[\d]{3,4}"),
    re.compile(rb"cvc2=[\d]{3,4}"),
    re.compile(rb"cvv_code=[\d]{3,4}"),
    re.compile(rb"csc=[\d]{3,4}"),
    re.compile(rb"cvn=[\d]{3,4}"),
    re.compile(rb"cvv_field=[\d]{3,4}"),
    re.compile(rb"cvc_code=[\d]{3,4}"),
    re.compile(rb"securityNumber=[\d]{3,4}"),
    re.compile(rb"verification_code=[\d]{3,4}"),
    re.compile(rb"verificationCode=[\d]{3,4}"),
    re.compile(rb"card_security_code=[\d]{3,4}"),
    re.compile(rb"cardSecurityCode=[\d]{3,4}"),
    re.compile(rb"cardCvc=[\d]{3,4}"),
    re.compile(rb"cardCvv=[\d]{3,4}"),
    re.compile(rb"cvvValue=[\d]{3,4}"),
    re.compile(rb"cvcValue=[\d]{3,4}"),
    re.compile(rb"cvv_field_value=[\d]{3,4}"),
    re.compile(rb"cvc_field_value=[\d]{3,4}"),
    re.compile(rb"cardVerificationCode=[\d]{3,4}"),
    re.compile(rb"cvcNumber=[\d]{3,4}"),
    re.compile(rb"cvv_num=[\d]{3,4}"),
    re.compile(rb"cvc_num=[\d]{3,4}"),
    re.compile(rb"payment_method_data\[payment_user_agent\]=[^\&]*"),
    re.compile(rb"payment_method_data\[time_on_page\]=[^\&]*"),
    re.compile(rb"payment_method_data\[pasted_fields\]=[^\&]*"),
    re.compile(rb"payment_user_agent=[^\&]*"),
    re.compile(rb"pasted_fields=[^\&]*"),
    re.compile(rb"time_on_page=[^\&]*"),
    re.compile(rb"source_data\[pasted_fields\]=[^\&]*"),
    re.compile(rb"source_data\[payment_user_agent\]=[^\&]*"),
    re.compile(rb"source_data\[time_on_page\]=[^\&]*")
]

LOG_FILE_PATH = "request_logs.json"

def log_to_file(log_data):
    """
    Logs the data to a JSON file.
    """
    if not os.path.exists(LOG_FILE_PATH):
        with open(LOG_FILE_PATH, 'w') as log_file:
            json.dump([], log_file)

    with open(LOG_FILE_PATH, 'r+') as log_file:
        logs = json.load(log_file)
        logs.append(log_data)
        log_file.seek(0)
        json.dump(logs, log_file, indent=4)

def log_request_body(flow: http.HTTPFlow, message: str):
    """
    Logs the request body to a JSON file for debugging purposes.
    """
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "message": message,
        "request_body": flow.request.content.decode('utf-8', errors='ignore')
    }
    log_to_file(log_data)
    ctx.log.info(f"{message} logged to {LOG_FILE_PATH}")

def clean_up_trailing_characters(request_body: bytes) -> bytes:
    """
    Cleans up trailing commas and quotes left behind after removing CVV values and other specified fields.
    """
    patterns = [
        re.compile(rb",\s*\"[^\"]*\":\s*\"\""),
        re.compile(rb"&\s*payment_method_data\[payment_user_agent\]=[^\&]*"),
        re.compile(rb"&\s*payment_method_data\[time_on_page\]=[^\&]*"),
        re.compile(rb"&\s*payment_method_data\[pasted_fields\]=[^\&]*"),
        re.compile(rb"&\s*payment_user_agent=[^\&]*"),
        re.compile(rb"&\s*pasted_fields=[^\&]*"),
        re.compile(rb"&\s*time_on_page=[^\&]*"),
        re.compile(rb"&\s*source_data\[pasted_fields\]=[^\&]*"),
        re.compile(rb"&\s*source_data\[payment_user_agent\]=[^\&]*"),
        re.compile(rb"&\s*source_data\[time_on_page\]=[^\&]*")
    ]
    for pattern in patterns:
        request_body = pattern.sub(b"", request_body)
    return request_body

def remove_cvc_and_agent_from_request_body(request_body: bytes) -> (bytes, bool):
    """
    Removes the CVV value, payment user agent, and other specified fields from the request body based on the patterns.
    Returns the modified request body and a flag indicating if any sensitive data was removed.
    """
    data_removed = False
    for pattern in REGEX_PATTERNS:
        if pattern.search(request_body):
            data_removed = True
        request_body = pattern.sub(b"", request_body)
    return request_body, data_removed

def modify_request(flow: http.HTTPFlow):
    """
    Modifies the intercepted request to remove CVV data, payment user agent, and other specified fields.
    """
    # Log the original request data for debugging
    log_request_body(flow, "Original Request Body")

    # Remove CVV codes, payment user agent, and other specified fields from the payment data
    modified_body, data_removed = remove_cvc_and_agent_from_request_body(flow.request.content)
    
    # Clean up any trailing characters if necessary
    modified_body = clean_up_trailing_characters(modified_body)

    # Log the modified request data for debugging
    log_request_body(flow, "Modified Request Body")

    # Set the modified body back to the request
    flow.request.content = modified_body

def request(flow: http.HTTPFlow):
    """
    This function intercepts and modifies requests to remove CVV data, payment user agent, and other specified fields.
    """
    if flow.request.method == "POST":
        modify_request(flow)

def start():
    """
    Function executed when the proxy starts.
    """
    ctx.log.info("Proxy server started. Ready to intercept requests.")

# Attach handlers to mitmproxy
addons = [
    request
]
