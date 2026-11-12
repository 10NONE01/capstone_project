
const express = require("express");
const path = require("node:path");

const app = express();
const PORT = 4100;

// Allow the server to read JSON requests
app.use(express.json());

// Check if our backend is running
app.get("/api/health", (req, res) => {
    res.json({
        status: "ok",
        message: "Mobile Auto Basics backend is running!"
    });
});

// Serve files ONLY from the public folder
app.use(express.static(path.join(__dirname, "public")));

// Start the server locally
app.listen(PORT, "127.0.0.1", () => {
    console.log(
        `Server running at http://127.0.0.1:${PORT}`
    );
});
