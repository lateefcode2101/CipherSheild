// script.js

// Example: Basic form validation
document.addEventListener('DOMContentLoaded', function() {
    const registerForm = document.querySelector('form[action="/register"]');
    const loginForm = document.querySelector('form[action="/login"]');
    const uploadForm = document.querySelector('form[action="/upload"]');

    if (registerForm) {
        registerForm.addEventListener('submit', function(event) {
            const username = registerForm.querySelector('input[name="username"]').value;
            const email = registerForm.querySelector('input[name="email"]').value;
            const password = registerForm.querySelector('input[name="password"]').value;

            if (username === '' || email === '' || password === '') {
                event.preventDefault();
                alert('All fields are required.');
            }
        });
    }

    if (loginForm) {
        loginForm.addEventListener('submit', function(event) {
            const username = loginForm.querySelector('input[name="username"]').value;
            const password = loginForm.querySelector('input[name="password"]').value;

            if (username === '' || password === '') {
                event.preventDefault();
                alert('Both fields are required.');
            }
        });
    }

    if (uploadForm) {
        uploadForm.addEventListener('submit', function(event) {
            const title = uploadForm.querySelector('input[name="title"]').value;
            const description = uploadForm.querySelector('textarea[name="description"]').value;

            if (title === '' || description === '') {
                event.preventDefault();
                alert('Both fields are required.');
            }
        });
    }
});
