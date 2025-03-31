require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const morgan = require("morgan");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const userRoutes = require("./routes/userRoutes");
const adminRoutes = require("./routes/adminRoutes");
const errorHandler = require("./middleware/errorHandler");
const logActivity = require("./middleware/logger"); // Corrected path

const app = express();

// Middleware
app.use(express.json()); // Parses JSON requests
app.use(morgan("combined")); // Logs requests in Apache format
app.use(logActivity); // Apply logging to all routes
app.use(helmet()); // Security headers

// CORS Configuration
const corsOptions = {
    origin: ["https://your-frontend.com"], // Allow only your frontend
    credentials: true, // Allow cookies
};
app.use(cors(corsOptions));

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests
    message: "Too many requests, please try again later.",
});
app.use(limiter); // Apply rate limiting

// Connect to MongoDB
const mongoURI = process.env.MONGO_URI;
mongoose
    .connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Connected to MongoDB ✅"))
    .catch((err) => console.error("MongoDB connection error:", err));

// Routes
app.use("/api/users", userRoutes);
app.use("/api/admin", adminRoutes);

app.get("/", (req, res) => {
    res.send("Horizon PMS Backend is Running! 🚀");
});

// Error Handling Middleware (Must be the last middleware)
app.use(errorHandler);

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
