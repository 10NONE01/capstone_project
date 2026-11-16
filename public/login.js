
const loginForm = document.getElementById("login-form");
const loginMessage = document.getElementById("login-message");

// Handle the login form
loginForm.addEventListener("submit", async (event) => {

    event.preventDefault();

    const email = document.getElementById("email").value;
    const passwordField = document.getElementById("password");
    const password = passwordField.value;

    // Get selected account type
    const selectedRole =
        document.getElementById("login-role").value;

    loginMessage.textContent = "Checking credentials...";

    try {

        // Send login information to Express
        const response = await fetch("/api/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            credentials: "same-origin",
            body: JSON.stringify({
                email: email,
                password: password,
                selectedRole: selectedRole
            })
        });

        const data = await response.json();

        // Clear password after sending
        passwordField.value = "";

        if (!response.ok) {
            loginMessage.textContent =
                data.error || "Login failed.";
            return;
        }

        // Authentication successful
        loginMessage.textContent = "Login successful!";

        // Open dashboard
        window.location.assign("dashboard.html");

    } catch (error) {

        passwordField.value = "";

        loginMessage.textContent =
            "Unable to connect to the server.";

    }

});

// Check whether the user already has a session
async function checkSession() {

    try {

        const response = await fetch("/api/me", {
            credentials: "same-origin"
        });

        if (response.ok) {
            window.location.replace("dashboard.html");
        }

    } catch (error) {
        // Remain on the login page
    }

}

checkSession();
