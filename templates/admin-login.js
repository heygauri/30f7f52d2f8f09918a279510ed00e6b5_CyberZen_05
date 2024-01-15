// admin-login.js

$(document).ready(function () {
    // Submit login form
    $("#loginForm").submit(function (event) {
        event.preventDefault();

        // Get values from the form
        var username = $("#username").val();
        var password = $("#password").val();

        // Validate the username and password
        if (!username) {
            alert("Please enter a username.");
            return;
        } else if (!password) {
            alert("Please enter a password.");
            return;
        }

        // Make an AJAX request to your server
        $.ajax({
            url: "http://127.0.0.1:5000/admin-login", // Replace with your server endpoint
            method: "POST",
            contentType: "application/json", // Set content type to JSON
            data: JSON.stringify({ username: username, password: password }), // Convert data to JSON
            success: function (response) {
                // Handle the response from the server
                alert(response.message);
                if (response.success) {
                    // Show the result container on success
                    $("#resultContainer").show();
                }
            },
            error: function (error) {
                console.error("Error:", error);
                alert("An error occurred. Please try again later.");
            }
        });
    });

    // Clear login form
    $("#clearButton").click(function () {
        $("#loginForm")[0].reset();
    });

    // Handle clicks on data buttons
    $("#websiteAnalysisData, #feedbackData, #adminUsersData").click(function () {
        // Replace these alerts with the logic to fetch and display the corresponding data
        alert("Feature not implemented yet.");
    });
});
