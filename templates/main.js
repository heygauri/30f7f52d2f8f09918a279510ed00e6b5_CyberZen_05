// static/main.js

$('#editButton').click(function () {
    location.reload(true); // Force a reload of the page
});


$(document).ready(function() {
    $('#urlForm').submit(function(event) {
        event.preventDefault();
        $('#analyzeButton').prop('disabled', true);
        const url = $('#urlInput').val();

        // Validate the URL using a simple regex
        if (isValidUrl(url)) {
            analyzeWebsite(url);
            $('.plz').hide();
        } else {
            $('#urlHelp').text("Please enter a valid URL.");
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
            //console.log(response);
            displayResult(response);
        },
        error: function(error) {
            console.error(error);
            alert('An error occurred during analysis.');
        }
    });
}

function displayUrls(allUrls) {
    // Clear the existing content
    $('.urls-container').empty();
    
    // Initialize i outside the loop
    var i = 1;

    // Display each URL
    allUrls.forEach(entry => {
        // Check if the entry has 'index' and 'url' properties
        if (entry && typeof entry === 'object' && 'index' in entry && 'url' in entry) {
            const index = entry.index;
            const url = entry.url;

            // Check if the URL starts with 'http'
            if (url.toLowerCase().startsWith('http')) {
                const urlElement = `<p>${i}. ${url}</p>`;
                i = i + 1;
                $('.urls-container').append(urlElement);
            }
        }
    });
}


function displayResult(result) {
    console.log(result);

    // Check if 'SSL Info' property exists
    if (result['SSL Info']) {
        // Extract 'SSL Info' from the result
        const sslInfo = result['SSL Info'];

        // Check if 'Domain Info' property exists
        if (sslInfo['Domain Info']) {
            const domainInfo = sslInfo['Domain Info'];

            // Update the HTML content of the SSL Information table
            $('.ssl-info-country').text(domainInfo['country'] || 'N/A');
            $('.ssl-info-creation-date').text(domainInfo['creation_date'] || 'N/A');
            $('.ssl-info-dnssec').text(domainInfo['dnssec'] || 'N/A');
            $('.ssl-info-domain-name').text(domainInfo['domain_name'] || 'N/A');
            $('.ssl-info-emails').text(domainInfo['emails'] || 'N/A');
            $('.ssl-info-expiration-date').text(domainInfo['expiration_date'] || 'N/A');
            $('.ssl-info-name-servers').text(domainInfo['name_servers'] ? domainInfo['name_servers'].join(', ') : 'N/A');
            $('.ssl-info-organization').text(domainInfo['organization'] || 'N/A');
            $('.ssl-info-registrar').text(domainInfo['registrar'] || 'N/A');
            $('.ssl-info-registrar-iana').text(domainInfo['registrar_iana'] || 'N/A');
            $('.ssl-info-registrar-url').text(domainInfo['registrar_url'] || 'N/A');
            $('.ssl-info-state').text(domainInfo['state'] || 'N/A');
            $('.ssl-info-status').text(domainInfo['status'] || 'N/A');
            $('.ssl-info-updated-date').text(domainInfo['updated_date'] || 'N/A');
        }
        else {
            $('.ssl-info-country, .ssl-info-creation-date, .ssl-info-dnssec, .ssl-info-domain-name, .ssl-info-emails, .ssl-info-expiration-date, .ssl-info-name-servers, .ssl-info-organization, .ssl-info-registrar, .ssl-info-registrar-iana, .ssl-info-registrar-url, .ssl-info-state, .ssl-info-status, .ssl-info-updated-date').text('N/A');
        }
        
        $('.ssl-info-protocol').text(sslInfo['Protocol'] || 'N/A');
        $('.ssl-info-valid-from').text(sslInfo['Valid From'] || 'N/A');
        $('.ssl-info-valid-until').text(sslInfo['Valid Until'] || 'N/A');
    }

    // Update other HTML content as needed
    $('.url').text(result.Url || 'N/A');
    
    if(result['Is Domain Legitimate']) {
        $('.isDomainLegitimate').addClass('legitimate').removeClass('phishing');
    } else {
        $('.isDomainLegitimate').addClass('phishing').removeClass('legitimate');
    }
    
    if(result['Is Certificate Valid']) {
        $('.isCertificateValid').addClass('legitimate').removeClass('phishing');
    } else {
        $('.isCertificateValid').addClass('phishing').removeClass('legitimate');
    }

    if(result['Is HTTPS']) {
        $('.isHttps').addClass('legitimate').removeClass('phishing');
    } else {
        $('.isHttps').addClass('phishing').removeClass('legitimate');
    }

    const mlResult = result['URL Analyzer Result'];
    var mlResultText = $('.mlResultText');

    // Update the text content
    mlResultText.text(mlResult['Is Website Fake']? "  This URL is Phishing": "  This URL is Legitimate");


    // Apply styling based on the value
    if (mlResult['Is Website Fake']) {
        mlResultText.addClass('phishing').removeClass('legitimate');
        temp = "phishing"
    } else {
        mlResultText.addClass('legitimate').removeClass('phishing');
        temp = "legitimate"
    }

    // Saving the analysis result in database
    const data = {
        url_input: result.Url || 'N/A',
        model_output: temp
    };
    
    fetch('http://127.0.0.1:5000/save-analysis', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
    })
    .then(response => response.json())
    .then(data => {
        console.log('Success:', data);
        // Handle success, update UI, etc.
    })
    .catch((error) => {
        console.error('Error:', error);
        // Handle error, show error message, etc.
    });
    
    if (result.Hyperlinks && result.Hyperlinks.length > 0) {
        // 'Hyperlinks' data is available, so display the HTML block
        $('.url-container').html('<h2 class="lead" style="display: inline-block; margin-right: 10px;"></h2><div class="url-container"></div>');

        // Update the content of '.urls-container' with the hyperlinks
        displayUrls(result.Hyperlinks);
    } else {
        // 'Hyperlinks' data is not available, so hide the HTML block
        $('.urls-container-heading').hide();
        $('.urls-container').hide();
    }
    console.log(result['Suspicious Images Content'])
    // // Display Suspicious Images Content
    // if (result['Suspicious Images Content']) {
    //     // 'Suspicious Images Content' data is available, so display the HTML block
    //     $('.suspicious-images-content').html('<h2 class="lead" style="display: inline-block; margin-right: 10px;">Suspicious Images Content</h2><div class="suspicious-images-content">' + result['Suspicious Images Content'] + '</div>');
    // } else {
    //     // 'Suspicious Images Content' data is not available, so hide the HTML block
    //     $('.suspicious-images-content-heading').hide();
    //     $('.suspicious-images-content').hide();
    // }

    if (result['Suspicious Images Content'] && result['Prediction Probability']) {
        // result['Suspicious Images Content'] is an array of sentences
        const sentences = result['Suspicious Images Content'].map(sentence => {
            return sentence;
        });
    
        const probabilities = result['Prediction Probability'].map(probability => {
            return probability;
        });
    
        const sentencesHTML = sentences.map((sentence, index) => {
            return `<p>${sentence} <br> ${probabilities[index]}</p>`;
        }).join('');
    
        $('.suspicious-images-content').html('<h2 class="lead" style="display: inline-block; margin-right: 10px;"></h2><div class="suspicious-images-content">' + sentencesHTML + '</div>');
    } else {
        // 'Suspicious Images Content' data is not available, so hide the HTML block
        $('.suspicious-images-content-heading').hide();
        $('.suspicious-images-content').hide();
    }


    $('#resultContainer').show();
}




