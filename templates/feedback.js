// feedback.js

$(document).ready(function () {
    // Submit feedback form
    $("#feedbackForm").submit(function (event) {
        event.preventDefault();

        // Get values from the form
        var feedback = $("#feedbackTextarea").val();

        // Validate the feedback content
        if (!feedback) {
            alert("Please enter feedback.");
            return;
        }

        // Make an AJAX request to your server to save feedback
        $.ajax({
            url: "http://127.0.0.1:5000/save-feedback", // Replace with your server endpoint
            method: "POST",
            contentType: "application/json", // Set content type to JSON
            data: JSON.stringify({ content: feedback }), // Convert data to JSON
            success: function (response) {
                // Handle the response from the server
                alert(response.message);
                if (response.success) {
                    // Clear the form on success
                    $("#feedbackForm")[0].reset();
                }
            },
            error: function (error) {
                console.error("Error:", error);
                alert("An error occurred. Please try again later.");
            }
        });
    });


    // Clear feedback form
    $("#clearButton").click(function () {
        // Clear the form
        $("#feedbackForm")[0].reset();
    });
});
