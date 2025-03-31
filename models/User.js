const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: "user" } // Default role as "user"
}, { timestamps: true });

const User = mongoose.model("User", UserSchema);

module.exports = User;
