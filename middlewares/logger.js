const fs = require("fs");
const path = require("path");

// Log file path
const logFilePath = path.join(__dirname, "../logs/activity.log");

// Function to log activity
const logActivity = (req, res, next) => {
    const logMessage = `${new Date().toISOString()} - ${req.method} ${req.originalUrl} - User: ${req.user?.userId || "Guest"}\n`;

    // Append log to file
    fs.appendFile(logFilePath, logMessage, (err) => {
        if (err) {
            console.error("Logging error:", err);
        }
    });

    next();
};

module.exports = logActivity;
