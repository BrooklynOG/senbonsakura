const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('frontend'));

// Database setup
const db = new sqlite3.Database('database.sqlite');

// Create tables
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Expenses table
  db.run(`CREATE TABLE IF NOT EXISTS expenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    description TEXT NOT NULL,
    amount REAL NOT NULL,
    category TEXT NOT NULL,
    date TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Chat history table
  db.run(`CREATE TABLE IF NOT EXISTS chat_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    messages TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Financial goals table
  db.run(`CREATE TABLE IF NOT EXISTS goals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    target_amount REAL NOT NULL,
    current_savings REAL NOT NULL,
    target_date TEXT NOT NULL,
    monthly_income REAL,
    monthly_expenses REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  console.log('Database tables created/verified');
});

// Groq API call function
async function callGroq(systemPrompt, userMessage) {
  const Groq = require('groq-sdk');
  const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });
  
  const completion = await groq.chat.completions.create({
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userMessage }
    ],
    model: 'llama-3.1-8b-instant',
    temperature: 0.7,
    max_tokens: 800
  });
  
  return completion.choices[0].message.content;
}

// ============= AUTHENTICATION ROUTES =============

// Register
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
      [username, email, hashedPassword],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(400).json({ error: 'Username or email already exists' });
          }
          return res.status(500).json({ error: err.message });
        }
        
        const token = jwt.sign({ id: this.lastID }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '7d' });
        res.json({ token, user: { id: this.lastID, username, email } });
      }
    );
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  db.get(`SELECT * FROM users WHERE username = ? OR email = ?`, [username, username], async (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
  });
});

// Verify token middleware
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  
  jwt.verify(token, process.env.JWT_SECRET || 'secretkey', (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.userId = decoded.id;
    next();
  });
}

// Get current user
app.get('/api/me', verifyToken, (req, res) => {
  db.get(`SELECT id, username, email, created_at FROM users WHERE id = ?`, [req.userId], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(user);
  });
});

// ============= EXPENSE ROUTES =============

// Get all expenses
app.get('/api/expenses', verifyToken, (req, res) => {
  db.all(`SELECT * FROM expenses WHERE user_id = ? ORDER BY date DESC`, [req.userId], (err, expenses) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(expenses);
  });
});

// Add expense
app.post('/api/expenses', verifyToken, (req, res) => {
  const { description, amount, category, date } = req.body;
  
  db.run(`INSERT INTO expenses (user_id, description, amount, category, date) VALUES (?, ?, ?, ?, ?)`,
    [req.userId, description, amount, category, date || new Date().toISOString().split('T')[0]],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, message: 'Expense added' });
    }
  );
});

// Delete expense
app.delete('/api/expenses/:id', verifyToken, (req, res) => {
  db.run(`DELETE FROM expenses WHERE id = ? AND user_id = ?`, [req.params.id, req.userId], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Expense deleted' });
  });
});

// ============= CHAT HISTORY ROUTES =============

// Get chat histories
app.get('/api/chats', verifyToken, (req, res) => {
  db.all(`SELECT id, title, created_at, updated_at FROM chat_history WHERE user_id = ? ORDER BY updated_at DESC`, [req.userId], (err, chats) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(chats);
  });
});

// Get single chat
app.get('/api/chats/:id', verifyToken, (req, res) => {
  db.get(`SELECT * FROM chat_history WHERE id = ? AND user_id = ?`, [req.params.id, req.userId], (err, chat) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(chat);
  });
});

// Save chat
app.post('/api/chats', verifyToken, (req, res) => {
  const { title, messages } = req.body;
  
  db.run(`INSERT INTO chat_history (user_id, title, messages) VALUES (?, ?, ?)`,
    [req.userId, title, JSON.stringify(messages)],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, message: 'Chat saved' });
    }
  );
});

// Update chat
app.put('/api/chats/:id', verifyToken, (req, res) => {
  const { title, messages } = req.body;
  
  db.run(`UPDATE chat_history SET title = ?, messages = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?`,
    [title, JSON.stringify(messages), req.params.id, req.userId],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Chat updated' });
    }
  );
});

// Delete chat
app.delete('/api/chats/:id', verifyToken, (req, res) => {
  db.run(`DELETE FROM chat_history WHERE id = ? AND user_id = ?`, [req.params.id, req.userId], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Chat deleted' });
  });
});

// ============= GOALS ROUTES =============

// Get all goals
app.get('/api/goals', verifyToken, (req, res) => {
  db.all(`SELECT * FROM goals WHERE user_id = ? ORDER BY created_at DESC`, [req.userId], (err, goals) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(goals);
  });
});

// Add goal
app.post('/api/goals', verifyToken, (req, res) => {
  const { name, target_amount, current_savings, target_date, monthly_income, monthly_expenses } = req.body;
  
  db.run(`INSERT INTO goals (user_id, name, target_amount, current_savings, target_date, monthly_income, monthly_expenses) 
          VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [req.userId, name, target_amount, current_savings, target_date, monthly_income, monthly_expenses],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, message: 'Goal saved' });
    }
  );
});

// Delete goal
app.delete('/api/goals/:id', verifyToken, (req, res) => {
  db.run(`DELETE FROM goals WHERE id = ? AND user_id = ?`, [req.params.id, req.userId], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Goal deleted' });
  });
});

// ============= AI ROUTES =============

// Chat with AI
app.post('/api/chat', verifyToken, async (req, res) => {
  const { message, history } = req.body;
  
  try {
    const reply = await callGroq(
      'You are a knowledgeable finance assistant specializing in Indian personal finance. Help with savings, investments, loans, budgeting, taxes. Use ₹. Use **bold** for key terms. Be concise.',
      message
    );
    res.json({ reply });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Analyze expenses
app.post('/api/analyze-expenses', verifyToken, async (req, res) => {
  const { expenses } = req.body;
  
  let total = 0;
  let bycat = {};
  expenses.forEach(exp => {
    total += exp.amount;
    bycat[exp.category] = (bycat[exp.category] || 0) + exp.amount;
  });
  
  const summary = Object.entries(bycat).map(([cat, amt]) => `${cat}: ₹${Math.round(amt)}`).join(', ');
  
  try {
    const analysis = await callGroq(
      'You are a financial advisor. Analyze expenses and give practical tips for an Indian user.',
      `Analyze expenses. Total spent: ₹${Math.round(total)}. By category: ${summary}. Give 3 concise, actionable tips to reduce spending and improve savings. Be specific and practical for India.`
    );
    res.json({ analysis });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get loan tips
app.post('/api/loan-tips', verifyToken, async (req, res) => {
  const { type, amount, rate, tenure } = req.body;
  
  try {
    const tips = await callGroq(
      'You are a loan advisor.',
      `For a ${type} of ₹${amount} at ${rate}% for ${tenure} months in India: give 3 concise tips on reducing interest burden, prepayment strategy, and one smart alternative.`
    );
    res.json({ tips });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get investment advice
app.post('/api/investment-advice', verifyToken, async (req, res) => {
  const { amount, rate, years, type } = req.body;
  
  try {
    const advice = await callGroq(
      'You are an investment advisor.',
      `SIP of ₹${amount}/month in a ${type} at ${rate}% for ${years} years in India. Give 3 concise tips: key risks, realistic return expectation, and 1 alternative fund type.`
    );
    res.json({ advice });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get goal plan
app.post('/api/goal-plan', verifyToken, async (req, res) => {
  const { name, target, current, months, income, expenses } = req.body;
  
  try {
    const plan = await callGroq(
      'You are a financial planner.',
      `Help me achieve a financial goal in India. Goal: ${name}. Target: ₹${target}. Current savings: ₹${current}. Timeframe: ${months} months. Monthly income: ₹${income}. Monthly expenses: ₹${expenses}. Give a practical step-by-step savings and investment plan with amounts.`
    );
    res.json({ plan });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Define term
app.post('/api/define-term', verifyToken, async (req, res) => {
  const { term } = req.body;
  
  try {
    const definition = await callGroq(
      'You are a finance educator.',
      `Define "${term}" in finance for a beginner in India. Include: 1) Simple definition, 2) Indian example with ₹, 3) Why it matters.`
    );
    res.json({ definition });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Visit http://localhost:${PORT} to use the app`);
});