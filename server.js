// server.js - Supabase Integrated Email Analysis Backend
const express = require('express');
const cors = require('cors');
const buildClaudePrompt = require('./utils/claudePrompt');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const { Anthropic } = require('@anthropic-ai/sdk');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);
const port = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const anthropic = new Anthropic({ apiKey: process.env.CLAUDE_API_KEY });
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:3000', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

const authenticateSupabaseToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });

  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) throw new Error('Invalid user');

    const dbUser = await pool.query('SELECT * FROM users WHERE email = $1', [user.email]);
    if (dbUser.rows.length === 0) {
      const inserted = await pool.query('INSERT INTO users (email) VALUES ($1) RETURNING *', [user.email]);
      req.user = inserted.rows[0];
    } else {
      req.user = dbUser.rows[0];
    }
    next();
  } catch (err) {
    console.error('Supabase auth error:', err);
    res.status(403).json({ error: 'Invalid or expired token' });
  }
};

function generateEmailHash(emailContent, sender, subject) {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(`${emailContent}${sender}${subject}`).digest('hex');
}

async function resetMonthlyCountIfNeeded(userId) {
  const result = await pool.query('SELECT month_reset_date FROM users WHERE id = $1', [userId]);
  const resetDate = new Date(result.rows[0].month_reset_date);
  const now = new Date();
  if (now.getMonth() !== resetDate.getMonth() || now.getFullYear() !== resetDate.getFullYear()) {
    await pool.query('UPDATE users SET emails_analyzed_this_month = 0, month_reset_date = $1 WHERE id = $2', [now.toISOString().split('T')[0], userId]);
  }
}

async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        plan VARCHAR(50) DEFAULT 'free',
        stripe_customer_id VARCHAR(255),
        emails_analyzed_this_month INTEGER DEFAULT 0,
        month_reset_date DATE DEFAULT CURRENT_DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_analyses (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        email_hash VARCHAR(64) UNIQUE NOT NULL,
        sender VARCHAR(255),
        subject TEXT,
        email_content TEXT NOT NULL,
        urgency INTEGER,
        response_pressure VARCHAR(50),
        action_type VARCHAR(50),
        has_money_request BOOLEAN,
        money_details JSONB,
        ai_confidence INTEGER,
        sentiment VARCHAR(50),
        processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        stripe_subscription_id VARCHAR(255) UNIQUE NOT NULL,
        status VARCHAR(50) NOT NULL,
        current_period_start TIMESTAMP,
        current_period_end TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ Database initialized');
  } catch (error) {
    console.error('❌ DB init error:', error);
  }
}

app.get('/', (req, res) => {
  res.json({ message: 'Email AI Backend is running!', timestamp: new Date().toISOString() });
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.get('/auth/profile', authenticateSupabaseToken, (req, res) => {
  res.json({ user: req.user });
});

// Removed Stripe session generation route

async function startServer() {
  await initializeDatabase();
  app.listen(port, () => {
    console.log(`🚀 Server running at http://localhost:${port}`);
  });
}

process.on('SIGTERM', () => {
  console.log('Shutting down...');
  pool.end();
  process.exit(0);
});

startServer().catch(console.error);
