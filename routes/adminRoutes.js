const express = require("express");
const router = express.Router();
const { authenticate, authorize } = require("../middleware/authMiddleware"); // Ensure correct path

// Admin Dashboard (Only accessible by admins)
router.get("/dashboard", authenticate, authorize(["admin"]), (req, res) => {
    res.json({ message: "Welcome to the Admin Dashboard", user: req.user });
});

module.exports = router;
