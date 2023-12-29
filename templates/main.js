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
            //console.log(response);
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

        // Update other HTML content as needed
        $('.ssl-info-protocol').text(sslInfo['Protocol'] || 'N/A');
        $('.ssl-info-valid-from').text(sslInfo['Valid From'] || 'N/A');
        $('.ssl-info-valid-until').text(sslInfo['Valid Until'] || 'N/A');
    }

    // Update other HTML content as needed
    $('.url').text(result.Url || 'N/A');
    $('.isDomainLegitimate').text(result['Is Domain Legitimate']);
    $('.isCertificateValid').text(result['Is Certificate Valid']);
    $('.isHttps').text(result['Is HTTPS']);
    $('.mlResultText').text(JSON.stringify(result['URL Analyzer Result'], null, 2));
    $('#resultContainer').show();
}




