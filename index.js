// Import packages
const db = require("./db");

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

// Create express app FIRST
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// -------------------------------
// TEMP ADMIN (FOR LEARNING ONLY)
// -------------------------------
const adminUser = {
  email: 'admin@safespace.com',
  // password = admin123
  passwordHash: bcrypt.hashSync('admin123', 10),
};

// -------------------------------
// TEST ROUTE
// -------------------------------
app.get('/test-login', async (req, res) => {
  const passwordMatch = await bcrypt.compare(
    'admin123',
    adminUser.passwordHash
  );

  res.json({
    emailMatch: adminUser.email === 'admin@safespace.com',
    passwordMatch: passwordMatch,
  });
});

// -------------------------------
// ADMIN LOGIN API
// -------------------------------
app.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;

  if (email !== adminUser.email) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const passwordMatch = await bcrypt.compare(
    password,
    adminUser.passwordHash
  );

  if (!passwordMatch) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign(
    { role: 'admin' },
    'SECRET_KEY',
    { expiresIn: '1h' }
  );

  res.json({
    message: 'Login successful',
    token: token,
  });
});

// -------------------------------
// ROOT ROUTE
// -------------------------------
app.get('/', (req, res) => {
  res.send('SafeSpace backend running');
});

// -------------------------------
// START SERVER
// -------------------------------
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
app.get("/db-test", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT 1");
    res.json({ message: "Database connected" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

