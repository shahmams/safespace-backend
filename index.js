// -------------------------------
// IMPORTS
// -------------------------------
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const db = require("./db");

// -------------------------------
// APP SETUP
// -------------------------------
const app = express();
app.use(cors());
app.use(express.json());

// -------------------------------
// TEMP ADMIN (FOR LEARNING ONLY)
// -------------------------------
const adminUser = {
  email: "admin@safespace.com",
  passwordHash: bcrypt.hashSync("admin123", 10),
};

// -------------------------------
// TEST LOGIN ROUTE
// -------------------------------
app.get("/test-login", async (req, res) => {
  const passwordMatch = await bcrypt.compare(
    "admin123",
    adminUser.passwordHash
  );

  res.json({
    emailMatch: adminUser.email === "admin@safespace.com",
    passwordMatch,
  });
});

// -------------------------------
// ADMIN LOGIN ROUTE
// -------------------------------
app.post("/admin/login", async (req, res) => {
  const { email, password } = req.body;

  if (email !== adminUser.email) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const passwordMatch = await bcrypt.compare(
    password,
    adminUser.passwordHash
  );

  if (!passwordMatch) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = jwt.sign(
    { role: "admin" },
    "SECRET_KEY",
    { expiresIn: "1h" }
  );

  res.json({
    message: "Login successful",
    token,
  });
});

// -------------------------------
// DB TEST ROUTE
// -------------------------------
app.get("/db-test", async (req, res) => {
  try {
    await db.query("SELECT 1");
    res.json({ message: "Database connected successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// -------------------------------
// USER REPORT SUBMISSION
// -------------------------------
app.post('/report', async (req, res) => {
  const { report_text, support_requested } = req.body;

  if (!report_text || report_text.trim() === '') {
    return res.status(400).json({ message: 'Report text is required' });
  }

  // Generate case ID
  const caseId = 'C-' + Math.floor(100000 + Math.random() * 900000);

  try {
    await db.query(
      `INSERT INTO reports 
       (case_id, report_text, support_requested, support_status) 
       VALUES (?, ?, ?, ?)`,
      [
        caseId,
        report_text,
        support_requested || false,
        support_requested ? 'PENDING' : 'NOT_REQUESTED',
      ]
    );

    res.json({
      message: 'Report submitted successfully',
      case_id: caseId,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------
// ROOT ROUTE
// -------------------------------
app.get("/", (req, res) => {
  res.send("SafeSpace backend running");
});

// -------------------------------
// START SERVER (MUST BE LAST)
// -------------------------------
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
