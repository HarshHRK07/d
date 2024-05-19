
import re
from mitmproxy import http, ctx
from mitmproxy.addonmanager import Loader
from mitmproxy.tools.web.master import WebMaster
from mitmproxy.web import webapp
from flask import Flask, request, render_template_string, jsonify

# Initialize the Flask app
app = Flask(__name__)

# Global variable to store domain keys mapping
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

# HTML template for the web form
HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>Add Domain Mapping</title>
</head>
<body>
    <div style="max-width: 600px; margin: auto;">
        <h1>Add Domain Mapping</h1>
        <form action="/add_mapping" method="post">
            <div>
                <label for="domain">API Domain:</label>
                <input type="text" id="domain" name="domain" required>
            </div>
            <div>
                <label for="regex">CVV Regex:</label>
                <input type="text" id="regex" name="regex" required>
            </div>
            <div>
                <button type="submit">Add Mapping</button>
            </div>
        </form>
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/add_mapping', methods=['POST'])
def add_mapping():
    domain = request.form.get('domain')
    regex = request.form.get('regex')
    
    if domain and regex:
        if domain not in DOMAIN_KEYS_MAPPING:
            DOMAIN_KEYS_MAPPING[domain] = []
        DOMAIN_KEYS_MAPPING[domain].append(re.compile(regex.encode()))
        return jsonify({"status": "success", "message": "Mapping added"}), 200
    else:
        return jsonify({"status": "error", "message": "Invalid input"}), 400

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
                
                # Clean up any trailing characters if necessary
                modified_body = clean_up_trailing_characters(modified_body, domain)

                # Log modified request data for debugging
                ctx.log.info(f"Modified Request Body for {domain}: {modified_body.decode('utf-8', errors='ignore')}")

                # Set the modified body back to the request
                flow.request.content = modified_body
            else:
                ctx.log.info(f"Skipping request interception for domain: {domain}")

def start():
    """
    Function executed when the proxy starts.
    """
    ctx.log.info("Proxy server started. Ready to intercept requests.")

    # Start Flask app on a separate thread
    from threading import Thread
    def run_app():
        app.run(host='0.0.0.0', port=5000)

    thread = Thread(target=run_app)
    thread.daemon = True
    thread.start()

# Attach handlers to mitmproxy
addons = [
    request
    ]
