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
  const { report_text, support_requested } = req.body;

  if (!report_text || report_text.trim() === "") {
    return res.status(400).json({
      message: "Report text is required",
    });
  }

  // 🔹 Generate case ID FIRST (always)
  const caseId = "C-" + Math.floor(100000 + Math.random() * 900000);

  try {
    // 🔹 STEP 1: Insert report immediately (guaranteed storage)
    await db.query(
      `INSERT INTO reports 
       (case_id, report_text, support_requested, support_status)
       VALUES (?, ?, ?, ?)`,
      [
        caseId,
        report_text,
        support_requested || false,
        support_requested ? "PENDING" : "NOT_REQUESTED",
      ]
    );

    // 🔹 STEP 2: Spam detection AFTER storing
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

    // 🔹 STEP 3: Gemini analysis ONLY for non-spam
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

    // 🔹 STEP 4: Update Gemini results
    await db.query(
      `UPDATE reports
       SET category = ?, severity = ?, location = ?
       WHERE case_id = ?`,
      [category, severity, location, caseId]
    );

    // 🔹 Final success response
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
