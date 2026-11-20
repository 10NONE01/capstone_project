
// ========================================
// MOBILE AUTO BASICS - DASHBOARD
// ========================================

// HTML elements
const dashboardTitle =
    document.getElementById("dashboard-title");

const dashboardMessage =
    document.getElementById("dashboard-message");

const customerDashboard =
    document.getElementById("customer-dashboard");

const mechanicDashboard =
    document.getElementById("mechanic-dashboard");

const adminDashboard =
    document.getElementById("admin-dashboard");

const apiResult =
    document.getElementById("dashboard-api-result");


// ========================================
// 1. LOAD AUTHENTICATED USER
// ========================================

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
            throw new Error(
                `Account request failed: HTTP ${response.status}`
            );
        }

        const data = await response.json();
        const user = data.user;

        if (!user || !user.role) {
            throw new Error("Invalid account information.");
        }

        dashboardTitle.textContent =
            `Welcome, ${user.name}!`;

        dashboardMessage.textContent = "";

        // Hide all dashboards
        customerDashboard.hidden = true;
        mechanicDashboard.hidden = true;
        adminDashboard.hidden = true;

        // CUSTOMER ROLE
        if (user.role === "customer") {

            customerDashboard.hidden = false;
            await loadAppointments();

        // MECHANIC ROLE
        } else if (user.role === "mechanic") {

            mechanicDashboard.hidden = false;
            await loadWorkTickets();

        // ADMINISTRATOR ROLE
        } else if (user.role === "admin") {

            adminDashboard.hidden = false;
            await loadAuditLogs();

        } else {

            throw new Error(
                `Unsupported role: ${user.role}`
            );
        }

    } catch (error) {

        console.error("Dashboard error:", error);

        dashboardMessage.textContent =
            "Unable to load your dashboard. Check the browser console.";
    }
}


// ========================================
// 2. CUSTOMER APPOINTMENTS
// ========================================

async function loadAppointments() {

    const list =
        document.getElementById("appointments-list");

    const message =
        document.getElementById("appointments-message");

    message.textContent = "Loading appointments...";

    try {

        const response = await fetch(
            "/api/customer/appointments",
            { credentials: "same-origin" }
        );

        if (!response.ok) {
            throw new Error(
                `Appointments API: HTTP ${response.status}`
            );
        }

        const data = await response.json();

        list.replaceChildren();

        const appointments = data.appointments;

        if (!Array.isArray(appointments)) {
            throw new Error("Invalid appointments response.");
        }

        if (appointments.length === 0) {
            message.textContent =
                "You don't have any appointments yet.";
            return;
        }

        message.textContent =
            "Here are your service appointments:";

        appointments.forEach((appointment) => {

            const card = document.createElement("div");
            card.className = "appointment-card";

            const title = document.createElement("h3");
            title.textContent = appointment.service;

            const vehicle = document.createElement("p");
            vehicle.textContent =
                `Vehicle: ${appointment.vehicle}`;

            const status = document.createElement("p");
            status.textContent =
                `Status: ${appointment.status}`;

            const id = document.createElement("p");
            id.textContent =
                `Appointment ID: ${appointment.id}`;

            card.append(title, vehicle, status, id);
            list.appendChild(card);
        });

    } catch (error) {

        console.error("Appointments error:", error);

        message.textContent =
            "Unable to load appointments.";
    }
}


// ========================================
// 3. MECHANIC WORK TICKETS
// ========================================

async function loadWorkTickets() {

    const list =
        document.getElementById("tickets-list");

    const message =
        document.getElementById("tickets-message");

    message.textContent = "Loading work tickets...";

    try {

        const response = await fetch(
            "/api/mechanic/tickets",
            { credentials: "same-origin" }
        );

        if (!response.ok) {
            throw new Error(
                `Mechanic API: HTTP ${response.status}`
            );
        }

        const data = await response.json();

        list.replaceChildren();

        const tickets = data.tickets;

        if (!Array.isArray(tickets)) {
            throw new Error("Invalid tickets response.");
        }

        if (tickets.length === 0) {
            message.textContent =
                "You have no assigned work tickets.";
            return;
        }

        message.textContent =
            "Here are your assigned repair jobs:";

        tickets.forEach((ticket) => {

            const card = document.createElement("div");
            card.className = "appointment-card";

            const title = document.createElement("h3");
            title.textContent = ticket.service;

            const customer = document.createElement("p");
            customer.textContent =
                `Customer: ${ticket.customer_name}`;

            const vehicle = document.createElement("p");
            vehicle.textContent =
                `Vehicle: ${ticket.vehicle}`;

            const status = document.createElement("p");
            status.textContent =
                `Status: ${ticket.status}`;

            const id = document.createElement("p");
            id.textContent =
                `Work Ticket ID: ${ticket.id}`;

            card.append(
                title,
                customer,
                vehicle,
                status,
                id
            );

            list.appendChild(card);
        });

    } catch (error) {

        console.error("Work tickets error:", error);

        message.textContent =
            "Unable to load work tickets.";
    }
}


// ========================================
// 4. ADMINISTRATOR AUDIT LOGS
// ========================================

async function loadAuditLogs() {

    const list =
        document.getElementById("audit-logs-list");

    const message =
        document.getElementById("admin-message");

    message.textContent = "Loading security logs...";

    try {

        const response = await fetch(
            "/api/admin/audit-logs",
            { credentials: "same-origin" }
        );

        if (!response.ok) {
            throw new Error(
                `Audit API: HTTP ${response.status}`
            );
        }

        const data = await response.json();

        list.replaceChildren();

        const logs = data.logs;

        if (!Array.isArray(logs)) {
            throw new Error("Invalid audit logs response.");
        }

        if (logs.length === 0) {
            message.textContent =
                "No security events have been recorded yet.";
            return;
        }

        message.textContent =
            `Displaying ${logs.length} recent security events.`;

        // Build the log table
        const table = document.createElement("table");
        table.className = "audit-table";

        const thead = document.createElement("thead");
        const headerRow = document.createElement("tr");

        const columns = [
            "ID",
            "Timestamp (UTC)",
            "User ID",
            "Event",
            "Resource",
            "Details"
        ];

        columns.forEach((column) => {

            const th = document.createElement("th");
            th.textContent = column;

            headerRow.appendChild(th);
        });

        thead.appendChild(headerRow);
        table.appendChild(thead);

        const tbody = document.createElement("tbody");

        logs.forEach((log) => {

            const row = document.createElement("tr");

            const values = [
                log.id,
                log.created_at,
                log.user_id ?? "Unknown",
                log.event_type,
                log.resource ?? "N/A",
                log.details ?? ""
            ];

            values.forEach((value) => {

                const td = document.createElement("td");

                // Display text safely
                td.textContent = String(value);

                row.appendChild(td);
            });

            tbody.appendChild(row);
        });

        table.appendChild(tbody);
        list.appendChild(table);

    } catch (error) {

        console.error("Audit logs error:", error);

        message.textContent =
            "Unable to load security audit logs.";
    }
}


// ========================================
// 5. TEST PROTECTED BACKEND APIS
// ========================================

async function testAPI(url) {

    try {

        const response = await fetch(url, {
            credentials: "same-origin"
        });

        const data = await response.json();

        apiResult.textContent =
            `HTTP ${response.status}\n` +
            JSON.stringify(data, null, 2);

    } catch (error) {

        console.error("API test error:", error);

        apiResult.textContent =
            "Could not contact the backend.";
    }
}


// Customer test button
document.getElementById("customer-api-test")
    .addEventListener("click", () => {

        testAPI("/api/customer/dashboard");
    });


// Mechanic test button
document.getElementById("mechanic-api-test")
    .addEventListener("click", () => {

        testAPI("/api/mechanic/tickets");
    });


// Admin refresh button
document.getElementById("refresh-audit-logs")
    .addEventListener("click", () => {

        loadAuditLogs();
    });


// ========================================
// 6. LOGOUT
// ========================================

document.getElementById("dashboard-logout")
    .addEventListener("click", async () => {

        try {

            const response = await fetch("/api/logout", {
                method: "POST",
                credentials: "same-origin"
            });

            if (!response.ok) {
                throw new Error("Logout failed.");
            }

            window.location.replace("login.html");

        } catch (error) {

            console.error("Logout error:", error);

            dashboardMessage.textContent =
                "Unable to log out. Please try again.";
        }
    });


// ========================================
// 7. START DASHBOARD
// ========================================

loadDashboard();
