document.addEventListener('DOMContentLoaded', function () {
  document.getElementById('loginForm').addEventListener('submit', function (event) {
    event.preventDefault();
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;

    // Check if username and password match the default credentials
    if (username === 'admin' && password === 'admin123') {
      // Redirect to the dashboard page
      window.location.href = "dashboard/dashboardNEW.html";
    } else {
      alert('Invalid username or password. Please try again.');
    }
  });
});
