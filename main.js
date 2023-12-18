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
        url: '/analyze',
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
    $('#resultText').text(result);
    $('#resultContainer').show();
}
