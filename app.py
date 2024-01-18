# app.py

from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
from datetime import datetime
from flask_cors import CORS
import matplotlib.pyplot as plt
import pandas as pd
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

import tensorflow as tf
import zipfile
import os

import string
from sklearn.feature_extraction.text import TfidfVectorizer
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
import sys
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import easyocr
import pymysql

# import mysql.connector


# app = Flask(__name__)
# CORS(app, resources={r"/*": {"origins": "*"}, r"/save-analysis": {"origins": "*"}})

# db_config = {
#     "host": "localhost",
#     "user": "sumitra",
#     "password": "Sumitra@2",
#     "database": "website_analyzer",
# }

# # Establish the MySQL connection
# mysql_connection = mysql.connector.connect(**db_config)

from flask import Flask, render_template, request, redirect, url_for, session
# from flask_sqlalchemy import SQLAlchemy

import secrets

app = Flask(__name__)
CORS(app)

# # Configure MySQL
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://sumitra:Sumitra@2@localhost/website_analyzer'  # Replace with your MySQL database details
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# # Initialize MySQL
# db = SQLAlchemy(app)

# # Your other imports and code go here

# if __name__ == '__main__':
#     app.run(debug=True)
# # from flask_mysqldb import MySQL


# # app = Flask(__name__)
# # CORS(app)

# # MySQL Configuration
# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'sumitra'
# app.config['MYSQL_PASSWORD'] = 'Sumitra@2'
# app.config['MYSQL_DB'] = 'website_analyzer'

# mysql = MySQL(app)

# # Generate a random 32-character hexadecimal string
# secret_key = secrets.token_hex(16)

# # Secret key for session
# app.secret_key = secret_key

import tensorflow as tf
print("Num GPUs Available: ", len(tf.config.experimental.list_physical_devices('GPU')))

from flask import render_template


# Login route
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Query the database to check if the user exists and the password is correct
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
        user = cur.fetchone()
        cur.close()

        if user:
            session['logged_in'] = True
            return true
        else:
            return false

    return false


# <----------------------------------------------------------------------------------------------------------------------->

# Function to clean and preprocess text
def clean_text(text):
    text = "".join([word.lower() for word in text if word not in string.punctuation])
    tokens = re.split('\W+', text)
    text = " ".join(tokens)
    return text

# Function to count punctuation
def count_punct(text):
    count = sum([1 for char in text if char in string.punctuation])
    return round(count/(len(text) - text.count(" ")), 3)*100


# <----------------------------------------------------------------------------------------------------------------------->

def initialize_driver():
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    driver = webdriver.Chrome(options=chrome_options)
    return driver

def download_image(image_url, save_path):
    try:
        # Skip downloading if the image has a .svg extension
        if image_url.lower().endswith('.svg'):
            print(f"Skipping SVG image: {image_url}")
            return None

        response = requests.get(image_url, stream=True)
        response.raise_for_status()

        with open(save_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)

        return save_path
    except Exception as e:
        print(f"Error downloading image from {image_url}: {e}")
        return None

def extract_image_urls(html_content, base_url):
    soup = BeautifulSoup(html_content, 'html.parser')

    # Extract URLs from img tags
    img_tags = soup.find_all('img', src=True)
    image_urls = [urljoin(base_url, img['src']) for img in img_tags]

    # Extract URLs from script tags (if used for lazy loading images)
    script_tags = soup.find_all('script', src=True)
    script_urls = [urljoin(base_url, script['src']) for script in script_tags]

    # Extract URLs from inline CSS styles
    style_tags = soup.find_all('style')
    for style in style_tags:
        css_urls = [urljoin(base_url, url.strip("url()").strip(" '\"")) for url in style.text.split('background-image:') if url.startswith(('http', 'https'))]
        image_urls.extend(css_urls)

    return image_urls

def extract_text_from_image(image_path):
    # Use EasyOCR to extract text
    try:
        reader = easyocr.Reader(['en'])
        results = reader.readtext(image_path)

        # Extracted text from the image
        extracted_text = ' '.join(result[1] for result in results)
        return extracted_text

    except Exception as e:
        print(f"Error extracting text from image {image_path}: {e}")
        return None

from pathlib import Path

# def extract_text_from_images(image_urls, max_images=10):
  
#     extracted_texts = []
    
#     # Process images in batches
#     batch_size = 4 
#     count = 0
#     for i in range(0, len(image_urls), batch_size):
#         batch_paths = []
        
#         for idx, image_url in enumerate(image_urls[i:i+batch_size]):
            
#             if idx >= max_images: 
#                 break
                
#             # Download image
#             save_path = f'Extracted_Images/{idx}_{os.path.basename(image_url)}'            
#             downloaded_image_path = download_image(image_url, save_path)
            
#             if downloaded_image_path:
#                 extracted_text = extract_text_from_image(downloaded_image_path)

#                 if extracted_text:
#                   extracted_texts.append(extracted_text)
#                   count = count+1
#                   print(extracted_text)

#                 # Delete the downloaded image
#                 os.remove(downloaded_image_path)
          
#     return extracted_texts

def extract_text_from_images(image_urls, max_images):
    extracted_texts = []
    
    # Process images in batches
    batch_size = 4
    count = 0
    
    for i in range(0, len(image_urls), batch_size):
        batch_paths = []
        
        for idx, image_url in enumerate(image_urls[i:i+batch_size]):
            
            if count >= max_images:
                break
            
            # Download image
            save_path = f'Extracted_Images/{idx}_{os.path.basename(image_url)}'            
            downloaded_image_path = download_image(image_url, save_path)
            
            if downloaded_image_path:
                extracted_text = extract_text_from_image(downloaded_image_path)

                if extracted_text:
                    extracted_texts.append(extracted_text)
                    count += 1
                    print(extracted_text)

                # Delete the downloaded image
                os.remove(downloaded_image_path)

        if count >= max_images:
            break
    
    return extracted_texts


def extract_text_batch(image_paths):

    # Load batch of images 
    batch_images = load_images(image_paths)    
    predictions = model(batch_images)
    
    # Extract text from predictions
    return text_extractor(predictions)

def extract_urls_with_selenium(url):
    driver = initialize_driver()
    driver.get(url)

    # Wait for dynamic content to load (you may need to adjust the wait time)
    driver.implicitly_wait(5)

    # Get the updated HTML content after dynamic content has loaded
    html_content = driver.page_source
    base_url = driver.current_url

    driver.quit()

    return html_content, base_url


# <------------------------------------------------------------------------------------------------------------------------>

# Import necessary libraries for hyperlink web scraping
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Function to initialize a Selenium WebDriver
def initialize_driver():
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')

    driver = webdriver.Chrome(options=chrome_options)
    return driver

# Function to extract all URLs from a dynamic website
def extract_all_urls_dynamic(website_url):
    driver = initialize_driver()
    driver.get(website_url)

    try:
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, 'body')))
        soup = BeautifulSoup(driver.page_source, 'html.parser')

        all_urls = []

        # Extract URLs from <a> tags
        for a_tag in soup.find_all('a', href=True):
            url = a_tag['href']
            all_urls.append(url)

        # Extract URLs from <img> tags
        for img_tag in soup.find_all('img', src=True):
            url = img_tag['src']
            all_urls.append(url)

        # Extract URLs from <amp-img> tags
        for amp_img_tag in soup.find_all('amp-img', src=True):
            url = amp_img_tag['src']
            all_urls.append(url)

        # Extract URLs from <amp-ad> tags
        for amp_ad_tag in soup.find_all('amp-ad', src=True):
            url = amp_ad_tag['src']
            all_urls.append(url)

        # Extract URLs from <iframe> tags
        for iframe_tag in soup.find_all('iframe', src=True):
            url = iframe_tag['src']
            all_urls.append(url)

        # Extract URLs from text using regex
        text_content = soup.get_text()
        text_urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text_content)
        all_urls.extend(text_urls)

        # Update only the URLs that start with "http" or "https"
        for i in range(len(all_urls)):
            if all_urls[i].startswith('http'):
                all_urls[i] = {'index': i + 1, 'url': all_urls[i]}

        return all_urls

    finally:
        driver.quit()


# <------------------------------------------------------------------------------------------------------------------------>

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

# 1.Domain of the URL (Domain)
def getDomain(url):
  domain = urlparse(url).netloc
  if re.match(r"^www.",domain):
	       domain = domain.replace("www.","")
  print("1",domain)
  return domain

# 2.Checks for IP address in URL (Have_IP)
def havingIP(url):
  try:
    ipaddress.ip_address(url)
    ip = 1
  except:
    ip = 0
  print("2",ip)
  return ip

# 3.Checks the presence of @ in URL (Have_At)
def haveAtSign(url):
  if "@" in url:
    at = 1
  else:
    at = 0
  print("3",at)
  return at

# 4.Finding the length of URL and categorizing (URL_Length)
def getLength(url):
  if len(url) < 54:
    length = 0
  else:
    length = 1
  print("4",length)
  return length

# 5.Gives number of '/' in URL (URL_Depth)
def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  print("5",depth)
  return depth

# 6.Checking for redirection '//' in the url (Redirection)
def redirection(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      print("6:1")
      return 1
    else:
      print("6:0")
      return 0
  else:
    print("6:0")
    return 0

# 7.Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def httpDomain(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    print("7:1")
    return 1
  else:
    print("7:0")
    return 0

#listing shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

# 8. Checking for Shortening Services in URL (Tiny_URL)
def tinyURL(url):
    match = re.search(shortening_services, url)
    if match:
        print("8:1")
        return 1
    else:
        print("8:0")
        return 0

# 9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        print("9:1")
        return 1            # phishing
    else:
        print("9:0")
        return 0            # legitimate

# 11.DNS Record availability (DNS_Record)
# obtained in the featureExtraction function itself

# 12. Is https protocol or http protocol
def ishttps(url):
    protocol = urlparse(url).scheme
    if protocol == 'https':
      print("12:1")
      return 1
    else:
      print("12:1")
      return 0

# 13.Survival time of domain: The difference between termination time and creation time (Domain_Age)
def domainAge(domain_name):
  creation_date = domain_name.creation_date
  expiration_date = domain_name.expiration_date
  if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
    try:
      creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      print("13:1")
      return 1
  if ((expiration_date is None) or (creation_date is None)):
      print("13:1")
      return 1
  elif ((type(expiration_date) is list) or (type(creation_date) is list)):
      print("13:1")
      return 1
  else:
    ageofdomain = abs((expiration_date - creation_date).days)
    if ((ageofdomain/30) < 6):
      age = 1
    else:
      age = 0
  print("13:",age)
  return age

# 14.End time of domain: The difference between termination time and current time (Domain_End)
def domainEnd(domain_name):
  expiration_date = domain_name.expiration_date
  if isinstance(expiration_date,str):
    try:
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      print("14:1")
      return 1
  if (expiration_date is None):
      print("14:1")
      return 1
  elif (type(expiration_date) is list):
      print("14:1")
      return 1
  else:
    today = datetime.now()
    end = abs((expiration_date - today).days)
    if ((end/30) < 6):
      end = 0
    else:
      end = 1
  print("14",end)
  return end

# 15. IFrame Redirection (iFrame)
def iframe(response):
  if response == "":
      print("15:1")
      return 1
  else:
      if re.findall(r"[<iframe>|<frameBorder>]", response.text):
          print("15:0")
          return 0
      else:
          print("15:1")
          return 1

# 16.Checks the effect of mouse over on status bar (Mouse_Over)
def mouseOver(response):
  if response == "" :
    print("16:1")
    return 1
  else:
    if re.findall("<script>.+onmouseover.+</script>", response.text):
      print("16:1")
      return 1
    else:
      print("16:0")
      return 0

# 17.Checks the status of the right click attribute (Right_Click)
def rightClick(response):
  if response == "":
    print("17:1")
    return 1
  else:
    if re.findall(r"event.button ?== ?2", response.text):
      print("17:0")
      return 0
    else:
      print("17:1")
      return 1

# 18.Checks the number of forwardings (Web_Forwards)
def forwarding(response):
  if response == "":
    print("18:1")
    return 1
  else:
    if len(response.history) <= 2:
      print("18:0")
      return 0
    else:
      print("18:1")
      return 1


#Function to extract features
def featureExtraction(url,label):

  features = []
  #Address bar based features (10)
  features.append(getDomain(url))
  features.append(havingIP(url))
  features.append(haveAtSign(url))
  features.append(getLength(url))
  features.append(getDepth(url))
  features.append(redirection(url))
  features.append(httpDomain(url))
  features.append(tinyURL(url))
  features.append(prefixSuffix(url))

  dns = 0
  try:
      domain_name = whois.whois(urlparse(url).netloc)
  except (whois.parser.PywhoisError, IOError, OSError) as e:
      # Handle the specific exception related to the error
      print(f"Error: {e}")
      dns = 1
  except Exception as e:
      # Handle other general exceptions if needed
      print(f"Unexpected Error: {e}")
      dns = 1

  features.append(dns)
  features.append(ishttps(url))
  features.append(1 if dns == 1 else domainAge(domain_name))
  features.append(1 if dns == 1 else domainEnd(domain_name))

  # HTML & Javascript based features (4)
  try:
    response = requests.get(url)
  except:
    response = ""
  features.append(iframe(response))
  features.append(mouseOver(response))
  features.append(rightClick(response))  
  features.append(forwarding(response))
  features.append(label)

  return features

def url_analyzer_model(url):
    print("Url Analyzer Start")
    
    #Load the machine learning model
    loaded_model = joblib.load('url_analyzer.pickle.dat')

    #Extracting the feautres & storing them in a list
    label = 0
    features = featureExtraction(url,label)
    print("\n", features, "\n")
    #converting the list to dataframe
    feature_names = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection',
                          'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Is_Https',
                          'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards', 'Label']

    feature_df = pd.DataFrame([features], columns=feature_names)

    # Make a prediction
    data = feature_df.drop(['Domain'], axis = 1).copy()
    prediction = loaded_model.predict(data.drop('Label', axis=1))
    
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

@app.route('/hyperlinks', methods=['POST'])
def hyperlinks():
    try:
        # Retrieving all hyperlinks present on the url
        target_website_url = request.form['url']
        all_urls = extract_all_urls_dynamic(target_website_url)
        hyperlink_result = {
            'Hyperlinks': all_urls
        }
        print(hyperlink_result)
        return jsonify(hyperlink_result)
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/suspicious', methods=['POST'])
def suspicious():
    try:
        target_url = request.form['url']

        # tensorflow NLP model integration
        # Unzip the folder
        # zip_path = 'model_6_savedmodel.zip'
        extract_path = 'model_6_savedmodel'
        # with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        #     zip_ref.extractall(extract_path)

        # Load the model
        loaded_model = tf.keras.models.load_model(extract_path)

        # Now you can use the loaded_model
        loaded_model_6 = tf.keras.models.load_model("model_6_savedmodel")
        
        suspicious_images_text = []
        prediction_probability = []

        # Retrieving Images present on the url
        html_content, base_url = extract_urls_with_selenium(target_url)
        image_urls = extract_image_urls(html_content, base_url)
        extracted_texts = extract_text_from_images(image_urls, 7)

        # Save extracted texts in a text file
        result_file_path = 'result.txt'
        with open(result_file_path, 'w') as result_file:
            for idx, text in enumerate(extracted_texts, 1):
                result_file.write(f"{text}\n")
        

        # Assuming you have a text file named "your_text_file.txt" with one sentence per line
        with open("result.txt", "r") as file:
            for line in file:
                # Use the loaded model to make predictions without printing progress
                pred_prob = loaded_model_6.predict([line], verbose=0)
                pred_label = tf.squeeze(tf.round(pred_prob)).numpy()

                # Print the prediction if the label is 1
                if pred_label == 1:
                    print("Predicted Label: Spam")
                    print(f"This sentence is suspicioius: {line.strip()}")
                    suspicious_images_text.append(f"This sentence is suspicioius: {line.strip()}")
                    print(f"Prediction Probability: {pred_prob[0][0]}")
                    prediction_probability.append(f"Prediction Probability: {pred_prob[0][0]}")
                    print("------------------------------")

        # Display the list of suspicious images or the message if no images are suspicious
            if not suspicious_images_text:
                suspicious_images_text.append(f"No image text found to be suspicious.")
                prediction_probability.append(f"")
                print("No image text is suspicious.")
            else:
                for suspicious_image in suspicious_images_text:
                    print(suspicious_image)

        # Combine SSL info and ML prediction into a single dictionary

        suspicious_result = {
            'Suspicious Images Content': suspicious_images_text,
            'Prediction Probability': prediction_probability
        }
        print(suspicious_result)
        return jsonify(suspicious_result)
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        url = request.form['url']
        
        # Predict website using ML model
        url_analyzer_result = url_analyzer_model(url)
        print("model result ", url_analyzer_result)
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

        valid_from = ssl_info['Valid From']
        valid_until = ssl_info['Valid Until']
        protocol = ssl_info['Protocol']
        domain_info = ssl_info['Domain Info']

        # Assuming 'valid_from' and 'valid_until' are keys in domain_info
        valid_from = domain_info.get('creation_date', None)
        valid_until = domain_info.get('expiration_date', None)

        # Handle expiration_date
        expiration_date = domain_info.get('expiration_date', None)
        if expiration_date is not None:
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]

            try:
                expiration_date = datetime.strptime(str(expiration_date), '%Y-%m-%d %H:%M:%S')
            except ValueError:
                print("Error: Invalid expiration date format.")
                expiration_date = None

            if expiration_date is not None:
                today = datetime.now()
                expiration_threshold = 365  # Set your threshold (e.g., 1 year)
                is_domain_legitimate = (expiration_date - today).days >= expiration_threshold
            else:
                is_domain_legitimate = False
        else:
            is_domain_legitimate = False

        # Handle valid_from and valid_until
        if valid_from is not None and valid_until is not None:
            try:
                current_date = datetime.now()
                valid_from_date = datetime.strptime(str(valid_from), '%Y-%m-%d %H:%M:%S')
                valid_until_date = datetime.strptime(str(valid_until), '%Y-%m-%d %H:%M:%S')

                is_certificate_valid = current_date >= valid_from_date and current_date <= valid_until_date
            except ValueError:
                print("Error: Invalid date format for certificate validity.")
                is_certificate_valid = False
        else:
            is_certificate_valid = False


        if is_certificate_valid:
            print("The certificate is valid.")
        else:
            print("The certificate is not valid.")

        print("\n expiration_date = ", expiration_date);
            
        # Check protocol used
        var = 'HTTPS' if url.startswith('https://') else ('HTTP' if url.startswith('http://') else 'N/A')
        is_https = var == 'HTTPS'

        if is_https:
            print("This URL uses HTTPS.")
        else:
            print("This URL uses HTTP.")

        if url_analyzer_result['Is Website Fake']:
            analysis_result = {
                'Url': url,
                'SSL Info': ssl_info,
                'Is Domain Legitimate': is_domain_legitimate,
                'Is Certificate Valid': is_certificate_valid,
                'Is HTTPS': is_https,
                'URL Analyzer Result': url_analyzer_result
            }

            print(analysis_result)
            return jsonify(analysis_result)
         
        # # Retrieving all hyperlinks present on the url
        # target_website_url = url
        # all_urls = extract_all_urls_dynamic(target_website_url)

# -------Third Subsystem--------------------------------------------

        # # Retrieving Images present on the url
        # target_url = url
        # html_content, base_url = extract_urls_with_selenium(target_url)
        # image_urls = extract_image_urls(html_content, base_url)
        # extracted_texts = extract_text_from_images(image_urls, 10)

        # # Save extracted texts in a text file
        # result_file_path = 'result.txt'
        # with open(result_file_path, 'w') as result_file:
        #     for idx, text in enumerate(extracted_texts, 1):
        #         result_file.write(f"{text}\n")
        
        # # tensorflow NLP model integration
        # # Unzip the folder
        # # zip_path = 'model_6_savedmodel.zip'
        # extract_path = 'model_6_savedmodel'

        # # with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        # #     zip_ref.extractall(extract_path)

        # # Load the model
        # loaded_model = tf.keras.models.load_model(extract_path)

        # # Now you can use the loaded_model
        # loaded_model_6 = tf.keras.models.load_model("model_6_savedmodel")
        
        # suspicious_images_text = []
        # prediction_probability = []

        # # Assuming you have a text file named "your_text_file.txt" with one sentence per line
        # with open("result.txt", "r") as file:
        #     for line in file:
        #         # Use the loaded model to make predictions without printing progress
        #         pred_prob = loaded_model_6.predict([line], verbose=0)
        #         pred_label = tf.squeeze(tf.round(pred_prob)).numpy()

        #         # Print the prediction if the label is 1
        #         if pred_label == 1:
        #             print("Predicted Label: Spam")
        #             print(f"This sentence is suspicioius: {line.strip()}")
        #             suspicious_images_text.append(f"This sentence is suspicioius: {line.strip()}")
        #             print(f"Prediction Probability: {pred_prob[0][0]}")
        #             prediction_probability.append(f"Prediction Probability: {pred_prob[0][0]}")
        #             print("------------------------------")

        # # Display the list of suspicious images or the message if no images are suspicious
        #     if not suspicious_images_text:
        #         suspicious_images_text.append(f"No image text found to be suspicious.")
        #         print("No image text is suspicious.")
        #     else:
        #         for suspicious_image in suspicious_images_text:
        #             print(suspicious_image)

        # Combine SSL info and ML prediction into a single dictionary

        analysis_result = {
            'Url': url,
            'SSL Info': ssl_info,
            'Is Domain Legitimate': is_domain_legitimate,
            'Is Certificate Valid': is_certificate_valid,
            'Is HTTPS': is_https,
            'URL Analyzer Result': url_analyzer_result
        }
        print(analysis_result)
        return jsonify(analysis_result)
    except Exception as e:
        return jsonify({'error': str(e)})

# <------------------------------------------------------------------------------------------------------------------------>

@app.route('/')
def index():
    return render_template('index.html')

# <--------------------------------------------MYSQL-DATABASE--------------------------------------------------------------->

# Add this route to your Flask app
@app.route('/show_table/<table_name>')
def show_table(table_name):
    # Example: Fetch data from the specified table
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM {table_name}")
    data = cur.fetchall()
    cur.close()

    return render_template('show_table.html', table_name=table_name, data=data)

# Save feedback
@app.route('/save-feedback', methods=['POST'])
def save_feedback():
    data = request.get_json()
    content = data.get('content')

    # Insert feedback into the database
    cur = mysql.connection.cursor()
    cur.execute('INSERT INTO feedback (content) VALUES (%s)', (content))
    mysql.connection.commit()
    cur.close()

    return jsonify(success=True, message='Feedback saved successfully'), 200

@app.route('/save-analysis', methods=['POST'])
def save_analysis():
    data = request.get_json()
    url_input = data.get('url_input')
    model_output = data.get('model_output')

    # Insert analysis result into the database
    cur = mysql.connection.cursor()
    cur.execute('INSERT INTO website_analysis (url_input, model_output) VALUES (%s, %s)', (url_input, model_output))
    mysql.connection.commit()
    cur.close()

    return jsonify(success=True, message='Analysis result saved successfully'), 200


if __name__ == '__main__':
    app.run(debug=True)
