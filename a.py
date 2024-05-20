from mitmproxy import http, ctx
import re
import json
import os

# Patterns to match CVV values and payment user agent in the request body
REGEX_PATTERNS = [
    rb"payment_method_data\[card\]\[cvc\]=[\d]{3,4}",
    rb"card\[cvc\]=[\d]{3,4}",
    rb"source_data\[card\]\[cvc\]=[\d]{3,4}",
    rb"encryptedSecurityCode\":\s*\"[^\"]+\"",
    rb"\"cvv\":\s*\"[\d]{3,4}\"",
    rb"cc_cscv=[\d]{3,4}",
    rb"card\[cvv\]=[\d]{3,4}",
    rb"card\[cvv2\]=[\d]{3,4}",
    rb"security_code=[\d]{3,4}",
    rb"securityCode=[\d]{3,4}",
    rb"cvvNumber=[\d]{3,4}",
    rb"card_verification_value=[\d]{3,4}",
    rb"cvc2=[\d]{3,4}",
    rb"cvv_code=[\d]{3,4}",
    rb"csc=[\d]{3,4}",
    rb"cvn=[\d]{3,4}",
    rb"cvv_field=[\d]{3,4}",
    rb"cvc_code=[\d]{3,4}",
    rb"securityNumber=[\d]{3,4}",
    rb"verification_code=[\d]{3,4}",
    rb"verificationCode=[\d]{3,4}",
    rb"card_security_code=[\d]{3,4}",
    rb"cardSecurityCode=[\d]{3,4}",
    rb"cardCvc=[\d]{3,4}",
    rb"cardCvv=[\d]{3,4}",
    rb"cvvValue=[\d]{3,4}",
    rb"cvcValue=[\d]{3,4}",
    rb"cvv_field_value=[\d]{3,4}",
    rb"cvc_field_value=[\d]{3,4}",
    rb"cardVerificationCode=[\d]{3,4}",
    rb"cvcNumber=[\d]{3,4}",
    rb"cvv_num=[\d]{3,4}",
    rb"cvc_num=[\d]{3,4}",
    rb"payment_method_data\[payment_user_agent\]=[^\&]*"
]

LOG_FILE = "cvv_log.json"

def log_request_body(flow: http.HTTPFlow, message: str):
    """
    Logs the request body for debugging purposes.
    """
    ctx.log.info(f"{message}: {flow.request.content.decode('utf-8', errors='ignore')}")

def log_cvv_data(flow: http.HTTPFlow):
    """
    Logs the details of a request containing CVV data to a file.
    """
    log_data = {
        "host": flow.request.host,
        "path": flow.request.path,
        "headers": dict(flow.request.headers),
        "timestamp": flow.request.timestamp_start,
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_data) + "\n")
    ctx.log.info(f"Logged CVV data to {LOG_FILE}")

def clean_up_trailing_characters(request_body: bytes) -> bytes:
    """
    Cleans up trailing commas and quotes left behind after removing CVV values.
    """
    cleaned_body = re.sub(rb",\s*\"[^\"]*\":\s*\"\"", b"", request_body)
    cleaned_body = re.sub(rb"&\s*payment_method_data\[payment_user_agent\]=[^\&]*", b"", cleaned_body)
    return cleaned_body

def remove_cvc_and_agent_from_request_body(request_body: bytes) -> (bytes, bool):
    """
    Removes the CVV value and payment user agent from the request body based on the patterns.
    Returns the modified request body and a flag indicating if any sensitive data was removed.
    """
    data_removed = False
    for pattern in REGEX_PATTERNS:
        if re.search(pattern, request_body):
            data_removed = True
        request_body = re.sub(pattern, b"", request_body)
    return request_body, data_removed

def modify_request(flow: http.HTTPFlow):
    """
    Modifies the intercepted request to remove CVV data and payment user agent.
    """
    # Log the original request data for debugging
    log_request_body(flow, "Original Request Body")

    # Remove CVV codes and payment user agent from the payment data
    modified_body, data_removed = remove_cvc_and_agent_from_request_body(flow.request.content)
    
    # Clean up any trailing characters if necessary
    modified_body = clean_up_trailing_characters(modified_body)

    # Log the modified request data for debugging
    log_request_body(flow, "Modified Request Body")

    # Set the modified body back to the request
    flow.request.content = modified_body

    # If sensitive data was removed, log the CVV data
    if data_removed:
        log_cvv_data(flow)

def request(flow: http.HTTPFlow):
    """
    This function intercepts and modifies requests to remove CVV data and payment user agent.
    """
    if flow.request.method == "POST":
        modify_request(flow)

def start():
    """
    Function executed when the proxy starts.
    """
    ctx.log.info("Proxy server started. Ready to intercept requests.")
    # Ensure the log file exists
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            f.write("")

# Attach handlers to mitmproxy
addons = [
    request
]
