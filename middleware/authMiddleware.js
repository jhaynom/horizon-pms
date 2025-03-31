const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

// Middleware to check authentication
const authenticate = (req, res, next) => {
    const token = req.cookies.token; // Use cookie instead of header
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ message: "Invalid token" });
    }
};

// Middleware to check authorization (Admin/User roles)
const authorize = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: "Forbidden: Access denied" });
        }
        next();
    };
};

// Rate limiter for login attempts
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Max 5 login attempts per 15 minutes
    message: "Too many login attempts. Please try again later.",
});

module.exports = { authenticate, authorize, loginLimiter };
