# Website Analyzer - AI/ML Fraud Detection System

## Project Overview

Welcome to the Website Analyzer project! This initiative addresses the pressing need for an Automated AI/ML System to Detect and Mitigate Online Fraud. The core objective is to create and implement an AI/ML-based system that can autonomously analyze and categorize online content, distinguishing between authentic and fake/fraudulent websites, advertisements, and customer care numbers.

## Project Name

**Website Analyzer**

## Project Description

"Website Analyzer" is a sophisticated web application designed for analyzing the legitimacy of given websites. The system employs various techniques, including domain legitimacy checks, SSL certificate validation, and a powerful machine learning model known as Url Analyzer. This model predicts website legitimacy based on 17 key features. The platform goes beyond traditional analysis by incorporating two additional subsystems: Extracted URLs - Hyperlink Fetcher and NLP Content Analysis System.

### Subsystems

1. **Extracted URLs - Hyperlink Fetcher:**
   - This subsystem serves as a hyperlink fetcher, extracting all hyperlinks present on the input URL's page. This feature provides users with valuable insights into the interconnected web of URLs associated with a given website.

2. **NLP Content Analysis System:**
   - The NLP Content Analysis System delves into the content of websites, extracting text from images using OCR (Optical Character Recognition). This NLP-driven analysis categorizes content as legitimate or potentially spammy, adding an extra layer of scrutiny to the evaluation process.

## Features

- **Domain Legitimacy Check:**
  - Analyzes the expiration date of the domain to determine its legitimacy.

- **SSL Certificate Validation:**
  - Checks the validity of the SSL certificate associated with the analyzed website.

- **HTTPS Detection:**
  - Determines whether the website uses HTTP or HTTPS.

- **Machine Learning Prediction:**
  - Leverages 17 key features to predict various aspects of the analyzed website, providing insights into potential security risks and overall legitimacy.

- **Images Content Analysis:**
  - Utilizes NLP and image recognition methods to assess the authenticity and accuracy of ad content and images on the website.

- **Customer Care Number Database Creation:**
  - Implements web scraping to build a database of fraudulent customer care numbers and uses a REST API to verify incoming numbers for potential scams. (Work in process)

- **Feedback Form:**
  - Provides a feedback mechanism to enhance the extension’s accuracy and adapt to evolving fraudulent tactics.

## Prerequisites

Ensure you have the following prerequisites installed:

- [Python](https://www.python.org/)
- [Flask](https://flask.palletsprojects.com/)
- [TensorFlow.js](https://www.tensorflow.org/js) for machine learning predictions
- [Selenium](https://www.selenium.dev/) for web scraping
- [Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/) for HTML parsing
- Chromium-Chrome driver for automated browsing

## Installation

1. Clone the repository:

   ```
   git clone https://github.com/heygauri/30f7f52d2f8f09918a279510ed00e6b5_CyberZen_05
   ```

2. Install dependencies:

   ```
   pip install -r requirements.txt
   ```

3. Run the application:

   ```
   python app.py
   ```

4. Open the application in your web browser: [http://localhost:5000/](http://localhost:5000/)

5. Enter the URL of the website you want to analyze in the provided user interface.

6. Click the "Analyze" button.

7. Review the analysis results, including domain legitimacy, SSL information, HTTPS usage, and machine learning predictions.

## Future Work

1. Develop a browser extension integrating URL analyzer for real-time fraudulent URL detection for end users.
2. Scale web analyzer system by implementing recursive hyperlink analysis for input URLs.
3. Advance to multilingual OCRs, followed by NLP models.

## Limitations

1. Utilizing TensorFlow in NLP model with GPU preference, currently restricted to CPUs due to resource limitations.
2. Url_Analyzer Model accuracy is 77%.
3. Ongoing efforts to improve efficiency in OCR processing.
   - The comprehensive scanning of all hyperlinks on the entire website is time-consuming, primarily due to resource limitations. While not every link has been checked yet, the extracted hyperlinks enable us to assess the presence of potential phishing URLs within legitimate websites.

## Contributing

Contributions are welcome! Please follow our [Contribution Guidelines](CONTRIBUTING.md) before submitting pull requests.

## License
This project is licensed under the MIT License. Feel free to use, modify, and distribute the code as needed.
