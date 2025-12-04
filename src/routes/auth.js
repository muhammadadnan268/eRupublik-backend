const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const User = require("../models/User");

const router = express.Router();

const signToken = (user) => {
  const secret = process.env.JWT_SECRET;
  const payload = { sub: user.id };
  return jwt.sign(payload, secret, { expiresIn: "7d" });
};

// Password validation helper
const validatePassword = (password) => {
  const errors = [];
  if (password.length < 8) {
    errors.push("Password must be at least 8 characters");
  }
  if (!/[a-z]/.test(password)) {
    errors.push("Password must contain at least one lowercase letter");
  }
  if (!/[A-Z]/.test(password)) {
    errors.push("Password must contain at least one uppercase letter");
  }
  if (!/[0-9]/.test(password)) {
    errors.push("Password must contain at least one number");
  }
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push("Password must contain at least one special character");
  }
  return errors;
};

// Name validation helper
const validateName = (name) => {
  if (!name || !name.trim()) {
    return "Citizen name is required";
  }
  if (name.trim().length < 3) {
    return "Citizen name must be at least 3 characters";
  }
  if (name.trim().length > 50) {
    return "Citizen name must be less than 50 characters";
  }
  if (!/^[a-zA-Z\s'-]+$/.test(name.trim())) {
    return "Citizen name can only contain letters, spaces, hyphens, and apostrophes";
  }
  return null;
};

// Email validation helper
const validateEmail = (email) => {
  if (!email || !email.trim()) {
    return "Email is required";
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return "Please enter a valid email address";
  }
  return null;
};

router.post("/signup", async (req, res) => {
  try {
    const { email, password, citizenName, citizenship } = req.body;
    
    // Check required fields
    if (!email || !password || !citizenName || !citizenship) {
      return res.status(400).json({ error: "email, password, citizenName, citizenship required" });
    }

    // Validate email
    const emailError = validateEmail(email);
    if (emailError) {
      return res.status(400).json({ error: emailError });
    }

    // Validate name
    const nameError = validateName(citizenName);
    if (nameError) {
      return res.status(400).json({ error: nameError });
    }

    // Validate password
    const passwordErrors = validatePassword(password);
    if (passwordErrors.length > 0) {
      return res.status(400).json({ error: passwordErrors[0] });
    }

    // Check if user exists
    const exists = await User.findOne({ email: email.toLowerCase().trim() });
    if (exists) return res.status(409).json({ error: "email already registered" });

    // Hash password and create user
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ 
      email: email.toLowerCase().trim(), 
      password: hash, 
      provider: "local", 
      citizenName: citizenName.trim(), 
      citizenship: citizenship.trim() 
    });
    const token = signToken(user);
    res.status(201).json({ token, user: { id: user.id, email: user.email, role: user.role, provider: user.provider, citizenName: user.citizenName, citizenship: user.citizenship } });
  } catch (e) {
    res.status(500).json({ error: "server error" });
  }
});

router.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "email and password required" });
    const user = await User.findOne({ email, provider: "local" });
    if (!user) return res.status(401).json({ error: "invalid credentials" });
    const ok = await bcrypt.compare(password, user.password || "");
    if (!ok) return res.status(401).json({ error: "invalid credentials" });
    const token = signToken(user);
    res.json({ token, user: { id: user.id, email: user.email, role: user.role, provider: user.provider, citizenName: user.citizenName, citizenship: user.citizenship } });
  } catch (e) {
    res.status(500).json({ error: "server error" });
  }
});

router.get("/facebook", passport.authenticate("facebook", { scope: ["email"], session: false }));

router.get(
  "/facebook/callback",
  passport.authenticate("facebook", { session: false, failureRedirect: "/api/auth/facebook/failure" }),
  (req, res) => {
    const token = signToken(req.user);
    res.json({ token, user: { id: req.user.id, email: req.user.email, role: req.user.role, provider: req.user.provider, citizenName: req.user.citizenName, citizenship: req.user.citizenship } });
  }
);

router.get("/facebook/failure", (req, res) => {
  res.status(401).json({ error: "facebook auth failed" });
});

module.exports = router;
