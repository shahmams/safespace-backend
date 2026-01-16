// -------------------------------
// ANONYMOUS ID GENERATOR
// -------------------------------
function generateAnonId() {
  return "U-" + Math.random().toString(36).substring(2, 10);
}

// -------------------------------
// IMPORTS
// -------------------------------
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const db = require("./db");
const { GoogleGenerativeAI } = require("@google/generative-ai");

// -------------------------------
// GEMINI SETUP
// -------------------------------
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

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
// TEMP COUNSELLOR (FOR LEARNING)
// -------------------------------
const counsellorUser = {
  email: "counsellor@safespace.com",
  passwordHash: bcrypt.hashSync("counsellor123", 10),
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
// COUNSELLOR LOGIN ROUTE
// -------------------------------
app.post("/counsellor/login", async (req, res) => {
  const { email, password } = req.body;

  if (email !== counsellorUser.email) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const passwordMatch = await bcrypt.compare(
    password,
    counsellorUser.passwordHash
  );

  if (!passwordMatch) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = jwt.sign(
    { role: "counsellor" },
    "SECRET_KEY",
    { expiresIn: "1h" }
  );

  res.json({
    message: "Login successful",
    token,
  });
});

// -------------------------------
// GET ANONYMOUS USER ID
// -------------------------------
app.get("/anon-id", (req, res) => {
  const anonId = generateAnonId();
  res.json({ anon_id: anonId });
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
// SPAM DETECTION
// -------------------------------
function classifySpam(text) {
  const lower = text.toLowerCase().trim();

  const spamKeywords = [
    "win", "free", "click", "subscribe",
    "offer", "http", "www", "buy now",
  ];

  for (const word of spamKeywords) {
    if (lower.includes(word)) return "spam";
  }

  if (/^[a-z]{4,}$/.test(lower)) return "spam";
  if (lower.split(" ").length <= 2) return "potential_spam";
  if (/(.)\1{4,}/.test(lower)) return "spam";

  return "valid";
}

// -------------------------------
// GEMINI ANALYSIS
// -------------------------------
async function analyzeWithGemini(text) {
  const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });

  const prompt = `
You are a campus safety analysis system.

Analyze the complaint and respond ONLY in valid JSON.

Allowed categories:
- Abuse and Harassment
- Mental Stress
- Emergency
- Ragging and Bullying
- College Safety
- Out of Scope

Allowed severity:
- LOW
- MEDIUM
- HIGH
- CRITICAL
- IGNORED

Rules:
- Short emotional distress is NOT Out of Scope
- Immediate danger must be CRITICAL
- Do not invent locations
- If location is unclear, return "Unknown"

Return JSON in this EXACT format:
{
  "category": "",
  "severity": "",
  "location": ""
}

Complaint:
"""${text}"""
`;

  const result = await model.generateContent(prompt);
  const responseText = result.response.text();

  const match = responseText.match(/\{[\s\S]*\}/);
  if (!match) throw new Error("Invalid Gemini response");

  return JSON.parse(match[0]);
}

// -------------------------------
// GEMINI OUTPUT VALIDATION
// -------------------------------
function validateGeminiOutput(result) {
  const allowedCategories = [
    "Abuse and Harassment",
    "Mental Stress",
    "Emergency",
    "Ragging and Bullying",
    "College Safety",
    "Out of Scope",
  ];

  const allowedSeverity = [
    "LOW", "MEDIUM", "HIGH", "CRITICAL", "IGNORED",
  ];

  if (!allowedCategories.includes(result.category)) {
    result.category = "Out of Scope";
  }

  if (!allowedSeverity.includes(result.severity)) {
    result.severity = "LOW";
  }

  if (typeof result.location !== "string") {
    result.location = "Unknown";
  }

  if (
    result.category === "Emergency" &&
    ["LOW", "MEDIUM"].includes(result.severity)
  ) {
    result.severity = "HIGH";
  }

  return result;
}

// -------------------------------
// USER REPORT SUBMISSION
// -------------------------------


app.post("/report", async (req, res) => {
  const { report_text, support_requested, anon_id } = req.body;

  if (!anon_id) {
  return res.status(400).json({
    message: "Anonymous ID missing",
  });
}
  if (!report_text || report_text.trim() === "") {
    return res.status(400).json({
      message: "Report text is required",
    });
  }

  const caseId = "C-" + Math.floor(100000 + Math.random() * 900000);

  try {
    await db.query(
      `INSERT INTO reports 
(case_id, anon_id, report_text, support_requested, support_status)
VALUES (?, ?, ?, ?, ?)
`,
      [
  caseId,
  anon_id,
  report_text,
  support_requested || false,
  support_requested ? "PENDING" : "NOT_REQUESTED",
]

    );

    const spamStatus = classifySpam(report_text);

    if (spamStatus === "spam") {
      await db.query(
        `UPDATE reports 
         SET is_spam = true, category = 'SPAM', severity = 'IGNORED'
         WHERE case_id = ?`,
        [caseId]
      );

      return res.json({
        message: "Report submitted successfully",
        case_id: caseId,
      });
    }

    let category = "Unknown";
    let severity = "LOW";
    let location = "Unknown";

    try {
      const geminiResult = await analyzeWithGemini(report_text);
      const validated = validateGeminiOutput(geminiResult);

      category = validated.category;
      severity = validated.severity;
      location = validated.location;
    } catch (err) {
      console.error("Gemini failed:", err.message);
    }

    await db.query(
      `UPDATE reports
       SET category = ?, severity = ?, location = ?
       WHERE case_id = ?`,
      [category, severity, location, caseId]
    );

    res.json({
      message: "Report submitted successfully",
      case_id: caseId,
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});
// -------------------------------
// GET REPORTS BY ANONYMOUS ID
// -------------------------------
app.get("/reports/by-anon/:anonId", async (req, res) => {
  const { anonId } = req.params;

  try {
    const [rows] = await db.query(
      `SELECT case_id, case_status, created_at
       FROM reports
       WHERE anon_id = ?
       ORDER BY created_at DESC`,
      [anonId]
    );

    res.json({
      reports: rows,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------
// ADMIN - VIEW SPAM REPORTS
// -------------------------------
app.get("/admin/reports/spam", async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT 
         case_id,
         report_text,
         case_status,
         created_at
       FROM reports
       WHERE is_spam = true
       ORDER BY created_at DESC`
    );

    res.json({
      count: rows.length,
      reports: rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------
// ADMIN - CLOSE REPORT
// -------------------------------
app.post("/admin/report/:caseId/close", async (req, res) => {
  const { caseId } = req.params;

  try {
    const [result] = await db.query(
      `UPDATE reports
       SET case_status = 'CLOSED'
       WHERE case_id = ?`,
      [caseId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        message: "Report not found",
      });
    }

    res.json({
      message: "Report closed successfully",
      case_id: caseId,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});
// -------------------------------
// ADMIN - VIEW ACTIVE REPORTS
// -------------------------------
app.get("/admin/reports/active", async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT case_id, category, severity, created_at
       FROM reports
       WHERE case_status = 'ACTIVE' AND is_spam = false
       ORDER BY created_at DESC`
    );

    res.json({
      reports: rows,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// -------------------------------
// ADMIN - VIEW CLOSED (PAST) REPORTS
// -------------------------------
app.get("/admin/reports/past", async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT case_id, category, severity, created_at
       FROM reports
       WHERE case_status = 'CLOSED'
       ORDER BY created_at DESC`
    );

    res.json({ reports: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------
// -------------------------------
// ADMIN - MARK REPORT AS NOT SPAM (AUTO CLASSIFY)
// -------------------------------
app.post("/admin/report/:caseId/mark-clean", async (req, res) => {
  const { caseId } = req.params;

  try {
    // 1️⃣ Get the report text
    const [rows] = await db.query(
      `SELECT report_text
       FROM reports
       WHERE case_id = ?`,
      [caseId]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        message: "Report not found",
      });
    }

    const reportText = rows[0].report_text;

    // 2️⃣ Run Gemini classification
    let category = "Out of Scope";
    let severity = "LOW";
    let location = "Unknown";

    try {
      const geminiResult = await analyzeWithGemini(reportText);
      const validated = validateGeminiOutput(geminiResult);

      category = validated.category;
      severity = validated.severity;
      location = validated.location;
    } catch (err) {
      console.error("Gemini failed during mark-clean:", err.message);
    }

    // 3️⃣ Update report as clean + classified
    await db.query(
      `UPDATE reports
       SET is_spam = false,
           category = ?,
           severity = ?,
           location = ?
       WHERE case_id = ?`,
      [category, severity, location, caseId]
    );

    res.json({
      message: "Report marked as not spam and classified",
      case_id: caseId,
      category,
      severity,
      location,
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});
// -------------------------------
// ADMIN - GET SINGLE REPORT DETAILS
// -------------------------------
app.get("/admin/report/:caseId", async (req, res) => {
  const { caseId } = req.params;

  try {
    const [rows] = await db.query(
      `SELECT * FROM reports WHERE case_id = ?`,
      [caseId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "Report not found" });
    }

    res.json({ report: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// -------------------------------
// ADMIN - SUGGEST COUNSELLING
// -------------------------------
app.post("/admin/report/:caseId/suggest-support", async (req, res) => {
  const { caseId } = req.params;

  try {
    await db.query(
      `UPDATE reports
       SET support_status = 'ADMIN_SUGGESTED'
       WHERE case_id = ?`,
      [caseId]
    );

    res.json({ message: "Counselling suggested to user" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// -------------------------------
// USER - ACCEPT COUNSELLING SUGGESTION
// -------------------------------
app.post("/report/:caseId/accept-support", async (req, res) => {
  const { caseId } = req.params;

  try {
    await db.query(
      `UPDATE reports
       SET support_requested = 1,
           support_status = 'PENDING'
       WHERE case_id = ?`,
      [caseId]
    );

    res.json({ message: "User accepted counselling suggestion" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// -------------------------------
// ADMIN - APPROVE COUNSELLING
// -------------------------------
app.post("/admin/report/:caseId/approve-support", async (req, res) => {
  const { caseId } = req.params;

  try {
    await db.query(
      `UPDATE reports
       SET support_status = 'APPROVED'
       WHERE case_id = ?`,
      [caseId]
    );

    res.json({ message: "Counselling approved" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// -------------------------------
// ADMIN - REJECT COUNSELLING
// -------------------------------
app.post("/admin/report/:caseId/reject-support", async (req, res) => {
  const { caseId } = req.params;

  try {
    await db.query(
      `UPDATE reports
       SET support_status = 'REJECTED'
       WHERE case_id = ?`,
      [caseId]
    );

    res.json({ message: "Counselling rejected" });
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
// START SERVER
// -------------------------------
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
