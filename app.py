# app.py

from flask import Flask, render_template, request, jsonify
from ml_model import predict_website

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        url = request.form['url']
        result = predict_website(url)
        return render_template('result.html', url=url, result=result)
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)
