// static/main.js

$(document).ready(function() {
    $('#urlForm').submit(function(event) {
        event.preventDefault();
        const url = $('#urlInput').val();

        // Validate the URL using a simple regex
        if (isValidUrl(url)) {
            analyzeWebsite(url);
        } else {
            alert('Please enter a valid URL.');
        }
    });
});

function isValidUrl(url) {
    // Simple URL validation using a regular expression
    const urlRegex = /^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$/;
    return urlRegex.test(url);
}

function analyzeWebsite(url) {
    $.ajax({
        type: 'POST',
        url: 'http://127.0.0.1:5000/analyze',
        data: {url: url},
        success: function(response) {
            displayResult(response);
        },
        error: function(error) {
            console.error(error);
            alert('An error occurred during analysis.');
        }
    });
}

function displayResult(result) {
    console.log(result);

    // Ensure that url, ssl_info, is_domain_legitimate, is_certificate_valid, is_https, and ml_result properties exist in the result object
    const url = result.Url;
    const sslInfoText = JSON.stringify(result['SSL Info']);
    const isDomainLegitimate = result['Is Domain Legitimate'];
    const isCertificateValid = result['Is Certificate Valid'];
    const isHttps = result['Is HTTPS'];
    const mlResultText = JSON.stringify(result['ML Result']);

    console.log(result.Url);
    console.log(result['SSL Info']);
    console.log(result['Is Domain Legitimate']);
    console.log(result['Is Certificate Valid']);
    console.log(result['Is HTTPS']);
    console.log(result['ML Result']);

    // Update the HTML content of each element
    $('.url').text(url);
    $('.sslInfoText').text(sslInfoText);
    $('.isDomainLegitimate').text(isDomainLegitimate);
    $('.isCertificateValid').text(isCertificateValid);
    $('.isHttps').text(isHttps);
    $('.mlResultText').text(mlResultText);
    $('#resultContainer').show();
}


