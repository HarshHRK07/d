import re
from mitmproxy import http, ctx

# Domains to intercept for modifying requests and corresponding keys
DOMAIN_KEYS_MAPPING = {
    "api.stripe.com": [
        rb"payment_method_data\[card\]\[cvc\]=[\d]{3,4}",
        rb"card\[cvc\]=[\d]{3,4}",
        rb"source_data\[card\]\[cvc\]=[\d]{3,4}"
    ],
    "cloud.boosteroid.com": [
        rb"encryptedSecurityCode\":\s*\"[\d]{3,4}\""
    ],
    "api.checkout.com": [
        rb"\"cvv\":\s*\"[\d]{3,4}\""
    ],
    "pci-connect.squareup.com": [
        rb"cvv\":\s*\"[\d]{3,4}\""
    ],
    "checkoutshopper-live.adyen.com": [
        rb"encryptedSecurityCode\":\s*\"[^\"]+\""
    ],
    "payments.vultr.com": [
        rb"cc_cscv=[\d]{3,4}"
    ],
    "payments.braintree-api.com": [
        rb"\"cvv\":\s*\"[\d]{3,4}\""
    ]
}

def remove_cvc_from_request_body(request_body, keys_to_remove):
    """
    Removes the CVC value from the request body based on the specified keys.
    """
    for key in keys_to_remove:
        request_body = re.sub(key, b"", request_body)
    return request_body

def request(flow: http.HTTPFlow):
    """
    This function intercepts and modifies requests to remove CVV data.
    """
    for domain, keys in DOMAIN_KEYS_MAPPING.items():
        if domain in flow.request.pretty_host:
            if keys:
                # Log original request data for debugging
                ctx.log.info(f"Original Request Body for {domain}: {flow.request.content.decode('utf-8', errors='ignore')}")

                # Remove CVV codes from the payment data
                modified_body = remove_cvc_from_request_body(flow.request.content, keys)
                
                # Log modified request data for debugging
                ctx.log.info(f"Modified Request Body for {domain}: {modified_body.decode('utf-8', errors='ignore')}")

                # Set the modified body back to the request
                flow.request.content = modified_body
            else:
                ctx.log.info(f"Skipping request interception for domain: {domain}")

def start():
    """
    Function executed when the proxy starts
    """
    ctx.log.info("Proxy server started. Ready to intercept requests.")

# Attach handlers to mitmproxy
addons = [
    request
]
