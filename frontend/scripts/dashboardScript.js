// Assuming you have a function to fetch the total number of videos streamed by the user
function fetchTotalVideos() {
    // Make an API request to your backend
    // Replace the placeholder URL with your actual API endpoint
    fetch('api/totalVideos')
        .then(response => response.json())
        .then(data => {
            // Update the totalVideos span with the fetched data
            document.getElementById('totalVideos').textContent = data.totalVideos;
        })
        .catch(error => console.error('Error fetching total videos:', error));
        document.getElementById('totalVideos').textContent = 'No Data Found';
}

// Call the fetchTotalVideos function when the page loads
window.onload = fetchTotalVideos;

function navigateToEncryption() {
    window.location.href = "../pages/encryptionPage.html";
}
function goBack() {
    window.history.back();
}
