# app.py

from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
from datetime import datetime
from flask_cors import CORS
import numpy as np
import urllib.request
import urllib.parse
import requests
import joblib
import socket
import whois
import json
import ssl
import re

app = Flask(__name__)
CORS(app)

def get_whois_info(url):
    try:
        # Use the 'whois' module to get domain information
        domain_info = whois.whois(url)

        # If 'creation_date' and 'expiration_date' are lists, take the first element
        if isinstance(domain_info, dict):
            if 'creation_date' in domain_info:
                # Check if 'creation_date' is a list, and take the first element
                if isinstance(domain_info['creation_date'], list):
                    domain_info['creation_date'] = domain_info['creation_date'][0]

            if 'expiration_date' in domain_info:
                # Check if 'expiration_date' is a list, and take the first element
                if isinstance(domain_info['expiration_date'], list):
                    domain_info['expiration_date'] = domain_info['expiration_date'][0]

        return domain_info
    except Exception as e:
        print(f"Error getting WHOIS information: {e}")
        return {}

def extract_date(date_info):
    if isinstance(date_info, list):
        return date_info[0] if date_info else datetime.now()
    elif isinstance(date_info, datetime):
        return date_info
    elif isinstance(date_info, str):
        return datetime.strptime(date_info, '%Y-%m-%d %H:%M:%S') if date_info else datetime.now()
    else:
        return datetime.now()

def fetch_response(url):
    try:
        response = requests.get(url)
        return response
    except Exception as e:
        print(f"Error fetching response: {e}")
        return None

def extract_features_from_url(url):
    print("Feature Extraction Start")
    # Initialize a dictionary with feature names and default values
    features = {
        'Have_IP': 0,
        'Have_At': 0,
        'URL_Length': 0,
        'URL_Depth': 0,
        'Redirection': 0,
        'https_Domain': 0,
        'TinyURL': 0,
        'Prefix/Suffix': 0,
        'DNS_Record': 0,
        'Web_Traffic': 0,
        'Domain_Age': 0,
        'Domain_End': 0,
        'iFrame': 0,
        'Mouse_Over': 0,
        'Right_Click': 0,
        'Web_Forwards': 0,
    }

    # 1 (phishing) or else 0 (legitimate)
    features['Have_IP'] = 1 if any(char.isdigit() for char in url) else 0
    features['Have_At'] = 1 if '@' in url else 0

    getLength = lambda url: 0 if len(url) < 54 else 1
    features['URL_Length'] = getLength(url)

    getDepth = lambda url: sum(1 for seg in urlparse(url).path.split('/') if seg)
    features['URL_Depth'] = getDepth(url)

    redirection = lambda url: 1 if url.rfind('//') > 6 and url.rfind('//') > 7 else 0
    features['Redirection'] = redirection(url)

    httpDomain = lambda url: 1 if 'https' in urlparse(url).netloc else 0
    features['https_Domain'] = httpDomain(url)

    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                        r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                        r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                        r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                        r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                        r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                        r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                        r"tr\.im|link\.zip\.net"

    tinyURL = lambda url: 1 if re.search(shortening_services, url) else 0
    features['TinyURL'] = tinyURL(url)

    prefixSuffix = lambda url: 1 if '-' in urlparse(url).netloc else 0
    features['Prefix/Suffix'] = prefixSuffix(url)

    # Lambda function to check web traffic based on Alexa rank
    web_traffic = lambda url: 1 if (lambda rank: 1 if rank < 100000 else 0)(
        int(
            BeautifulSoup(
                urllib.request.urlopen(f"http://data.alexa.com/data?cli=10&dat=s&url={urllib.parse.quote(url)}").read(),
                "xml"
            ).find("REACH", attrs={"RANK": True})['RANK']
        )
    ) else 0

    # Set a default value for 'Web_Traffic' in case of an error during web scraping
    features['Web_Traffic'] = 0

    try:
        # Try to get the actual value for 'Web_Traffic'
        features['Web_Traffic'] = web_traffic(url)
    except urllib.error.URLError as e:
        # Print an error message and use the default value
        print(f"Error during web scraping: {e}")
        features['Web_Traffic'] = 0  # Set a default value, adjust as needed
    
    parsed_url = urlparse(url)
    domain_name = parsed_url.netloc

    domain_info = get_whois_info(url)


    domainAge = lambda domain_info: (lambda age: 1 if age < 6 else 0)(
        abs(
            (
                extract_date(domain_info.get('expiration_date', datetime.now()))
                - extract_date(domain_info.get('creation_date', datetime.now()))
            ).days
        ) / 30
    ) if not (
        isinstance(domain_info.get('creation_date'), (str, list))
        or isinstance(domain_info.get('expiration_date'), (str, list, type(None)))
    ) else 1
    features['Domain_Age'] = domainAge(domain_info)

    domainEnd = lambda domain_info: (lambda end: 0 if end < 6 else 1)(
        abs(
            (
                extract_date(domain_info.get('expiration_date', datetime.now()))
                - datetime.now()
            ).days
        ) / 30
    ) if not isinstance(domain_info.get('expiration_date'), (str, list, type(None))) else 1
    features['Domain_End'] = domainEnd(domain_info)

    response = fetch_response(url)

    iframe = lambda response: 1 if response is None or response.text is None or response.text == "" or re.findall(r"[|]", response.text) else 0
    features['iFrame'] = iframe(response)

    mouseOver = lambda response: 1 if response is None or response.text is None or response.text == "" or re.findall("", response.text) else 0
    features['Mouse_Over'] = mouseOver(response)

    rightClick = lambda response: 1 if response is None or response.text is None or response.text == "" or not re.findall(r"event.button ?== ?2", response.text) else 0
    features['Right_Click'] = rightClick(response)

    forwarding = lambda response: 1 if response is None or response.text is None or response.text == "" or len(response.history) <= 2 else 0
    features['Web_Forwards'] = forwarding(response)

    print("Feature Extraction End")

    # Return features as a dictionary
    return features



def url_analyzer_model(url):
    print("Url Analyzer Start")
    
    # Extract features from the URL
    features = extract_features_from_url(url)
    
    # List of features in the correct order
    feature_order = [
        'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection', 'https_Domain', 'TinyURL',
        'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 'Domain_Age', 'Domain_End', 'iFrame',
        'Mouse_Over', 'Right_Click', 'Web_Forwards'
    ]
    
    # Make sure that the features dictionary has all the required features
    features = {feature: features.get(feature, 0) for feature in feature_order}
    
    # Load the machine learning model
    loaded_model = joblib.load('url_analyzer.pkl')
    
    # Reshape the features for prediction
    features_array = np.array(list(features.values())).reshape(1, -1)
    
    # Make a prediction
    prediction = loaded_model.predict(features_array)
    
    print("Url Analyzer End")

    return {
        'Is Website Fake': bool(prediction[0])
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
        print("printing domain_info")
        print(domain_info)

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
        url_analyzer_result = url_analyzer_model(url)

        # Get SSL information
        ssl_info = get_certificate_information(url)
        
        if not ssl_info:

            analysis_result = {
            'Url': url,
            'SSL Info': {},
            'Is Domain Legitimate': False,
            'Is Certificate Valid': False,
            'Is HTTPS': False,
            'URL Analyzer Result': url_analyzer_result
            }

            print(analysis_result)
            return jsonify(analysis_result)

        else:
            valid_from = ssl_info['Valid From']
            valid_until = ssl_info['Valid Until']
            protocol = ssl_info['Protocol']
            domain_info = ssl_info['Domain Info']

        # Extract the expiration date from WHOIS information
        expiration_date = domain_info.get('expiration_date', None)

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
            'ML Result': url_analyzer_result
        }
        print(analysis_result)
        return jsonify(analysis_result)
    except Exception as e:
        return jsonify({'error': str(e)})


if __name__ == '__main__':
    app.run(debug=True)
