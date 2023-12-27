# app.py

from flask import Flask, render_template, request, jsonify
from ml_model import predict_website
import ssl
import socket
from datetime import datetime
import whois
from flask_cors import CORS
import json

app = Flask(__name__)
CORS(app)

def predict_website(url):
    print("predict_website executed")
    # Replace this with your actual ML model prediction logic
    # For now, returning a dummy result
    return {
        'Is Website Fake': False
    }

def get_certificate_information(url):
    try:
        # Adding "https://" to the URL if no protocol is specified
        if '://' not in url:
            url = 'https://' + url

        hostname = url.split("://")[1].split("/")[0]
        port = 443  # Default HTTPS port

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # Extract relevant information from the certificate
        subject = dict(x[0] for x in cert['subject'])
        issued_to = subject.get('commonName', None)
        valid_from = cert['notBefore']
        valid_until = cert['notAfter']

        # Check domain ownership information using WHOIS
        domain_info = whois.whois(hostname)

        # Determine the protocol used (HTTP/HTTPS)
        protocol = "HTTPS" if port == 443 else "HTTP"

        return {
            'Valid From': valid_from,
            'Valid Until': valid_until,
            'Protocol': protocol,
            'Domain Info': domain_info
        }
    except (ssl.SSLError, socket.gaierror, whois.parser.PywhoisError) as e:
        # Return None to indicate an error occurred
        print('Certificate information retrieval error')
        return {}

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        url = request.form['url']
        
        # Predict website using ML model
        result = predict_website(url)

        # Get SSL information
        ssl_info = get_certificate_information(url)
        
        if not ssl_info:

            analysis_result = {
            'Url': url,
            'SSL Info': {},
            'Is Domain Legitimate': False,
            'Is Certificate Valid': False,
            'Is HTTPS': False,
            'ML Result': result
            }

            return render_template('index.html', analysis_result=analysis_result)

        else:
            valid_from = ssl_info['Valid From']
            valid_until = ssl_info['Valid Until']
            protocol = ssl_info['Protocol']
            domain_info = ssl_info['Domain Info']

        # Extract the expiration date from WHOIS information
        expiration_date = domain_info['expiration_date']

        # Check if expiration_date is a list and get the first element
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        expiration_date = datetime.strptime(str(expiration_date), '%Y-%m-%d %H:%M:%S')

        today = datetime.now()
        expiration_threshold = 365  # Set your threshold (e.g., 1 year)
        is_domain_legitimate = (expiration_date - today).days > expiration_threshold

        # Check if the certificate is still valid
        current_date = datetime.now()
        valid_from_date = datetime.strptime(valid_from, "%b %d %H:%M:%S %Y %Z")
        valid_until_date = datetime.strptime(valid_until, "%b %d %H:%M:%S %Y %Z")

        is_certificate_valid = current_date >= valid_from_date and current_date <= valid_until_date

        if is_certificate_valid:
            print("The certificate is valid.")
        else:
            print("The certificate is not valid.")

        # Check protocol used
        is_https = protocol == 'HTTPS'
        if is_https:
            print("This website uses HTTPS.")
        else:
            print("This website uses HTTP.")

        
        # Combine SSL info and ML prediction into a single dictionary
        analysis_result = {
            'Url': url,
            'SSL Info': ssl_info,
            'Is Domain Legitimate': is_domain_legitimate,
            'Is Certificate Valid': is_certificate_valid,
            'Is HTTPS': is_https,
            'ML Result': result
        }
        print(analysis_result)
        return render_template('index.html', analysis_result=analysis_result)
    except Exception as e:
        return jsonify({'error': str(e)})


if __name__ == '__main__':
    app.run(debug=True)
