from mitmproxy import http, ctx
import re
import os
import json

# Load patterns from an external JSON configuration file
def load_patterns(filename: str):
    with open(filename, 'r') as file:
        return json.load(file)

# Load regex patterns
try:
    REGEX_PATTERNS = [re.compile(pattern.encode()) for pattern in load_patterns("patterns.json")]
except Exception as e:
    ctx.log.error(f"Error loading patterns: {e}")
    REGEX_PATTERNS = []

def log_request_body(flow: http.HTTPFlow, message: str, level: str = "info"):
    """
    Logs the request body for debugging purposes.
    """
    log_func = getattr(ctx.log, level, ctx.log.info)
    log_func(f"{message}: {flow.request.content.decode('utf-8', errors='ignore')}")

def clean_up_trailing_characters(request_body: bytes) -> bytes:
    """
    Cleans up trailing commas, quotes, or ampersands left behind after removing CVV values and other specified fields.
    """
    cleaned_body = re.sub(rb",\s*\"[^\"]*\":\s*\"\"", b"", request_body)
    cleaned_body = re.sub(rb"[&]?\s*[a-zA-Z0-9_]+\[?[a-zA-Z0-9_]*\]?\=[^\&]*", b"", cleaned_body)
    cleaned_body = re.sub(rb"[&]$", b"", cleaned_body)  # Remove trailing '&' if any
    return cleaned_body

def remove_sensitive_data(request_body: bytes) -> (bytes, bool):
    """
    Removes the sensitive data from the request body based on the patterns.
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
    Modifies the intercepted request to remove sensitive data.
    """
    # Log the original request data for debugging
    log_request_body(flow, "Original Request Body")

    # Remove sensitive data from the request
    modified_body, data_removed = remove_sensitive_data(flow.request.content)
    
    # Clean up any trailing characters if necessary
    modified_body = clean_up_trailing_characters(modified_body)

    # Log the modified request data for debugging
    log_request_body(flow, "Modified Request Body")

    # Set the modified body back to the request
    flow.request.content = modified_body

def request(flow: http.HTTPFlow):
    """
    This function intercepts and modifies requests to remove sensitive data.
    """
    if flow.request.method in ["POST", "PUT"]:  # Include PUT requests if needed
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
