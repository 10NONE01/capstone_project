
const dashboardTitle =
    document.getElementById("dashboard-title");

const dashboardMessage =
    document.getElementById("dashboard-message");

const customerDashboard =
    document.getElementById("customer-dashboard");

const mechanicDashboard =
    document.getElementById("mechanic-dashboard");

const apiResult =
    document.getElementById("dashboard-api-result");

// Load authenticated user
async function loadDashboard() {
    try {
        const response = await fetch("/api/me", {
            credentials: "same-origin"
        });

        if (response.status === 401) {
            window.location.replace("login.html");
            return;
        }

        if (!response.ok) {
            throw new Error("Unable to load account");
        }

        const data = await response.json();
        const user = data.user;

        dashboardTitle.textContent = `Welcome, ${user.name}!`;

        if (user.role === "customer") {
            customerDashboard.hidden = false;

        } else if (user.role === "mechanic") {
            mechanicDashboard.hidden = false;

        } else {
            throw new Error("Unknown role");
        }

    } catch {
        dashboardMessage.textContent =
            "Unable to load your dashboard.";
    }
}

// Test protected backend API
async function testAPI(url) {
    try {
        const response = await fetch(url, {
            credentials: "same-origin"
        });

        const data = await response.json();

        apiResult.textContent =
            `HTTP ${response.status}\n` +
            JSON.stringify(data, null, 2);

    } catch {
        apiResult.textContent =
            "Could not contact the backend.";
    }
}

// Customer API test
document.getElementById("customer-api-test")
    .addEventListener("click", () => {
        testAPI("/api/customer/dashboard");
    });

// Mechanic API test
document.getElementById("mechanic-api-test")
    .addEventListener("click", () => {
        testAPI("/api/mechanic/tickets");
    });

// Logout
document.getElementById("dashboard-logout")
    .addEventListener("click", async () => {
        try {
            const response = await fetch("/api/logout", {
                method: "POST",
                credentials: "same-origin"
            });

            if (!response.ok) {
                throw new Error("Logout failed");
            }

            window.location.replace("login.html");

        } catch {
            dashboardMessage.textContent =
                "Could not log out.";
        }
    });

loadDashboard();
