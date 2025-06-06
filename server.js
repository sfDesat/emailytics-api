// server.js - Supabase Integrated Email Analysis Backend
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const { Anthropic } = require('@anthropic-ai/sdk');
const stripe = require('stripe');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const anthropic = new Anthropic({ apiKey: process.env.CLAUDE_API_KEY });
const stripeClient = stripe(process.env.STRIPE_SECRET_KEY);
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
      const inserted = await pool.query(
        'INSERT INTO users (email) VALUES ($1) RETURNING *',
        [user.email]
      );
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

app.post('/payments/create-checkout-session', authenticateSupabaseToken, async (req, res) => {
  try {
    const { priceId } = req.body;
    const session = await stripeClient.checkout.sessions.create({
      customer: req.user.stripe_customer_id,
      payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      mode: 'subscription',
      success_url: `${process.env.FRONTEND_URL}/dashboard?success=true`,
      cancel_url: `${process.env.FRONTEND_URL}/pricing?canceled=true`,
      metadata: { userId: req.user.id.toString() }
    });
    res.json({ sessionId: session.id });
  } catch (error) {
    console.error('❌ Stripe checkout error:', error);
    res.status(500).json({ error: 'Stripe session failed' });
  }
});

app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  try {
    const event = stripeClient.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    switch (event.type) {
      case 'checkout.session.completed':
        const session = event.data.object;
        const userId = session.metadata.userId;
        await pool.query('UPDATE users SET plan = $1 WHERE id = $2', ['paid', userId]);
        const subscription = await stripeClient.subscriptions.retrieve(session.subscription);
        await pool.query(`INSERT INTO subscriptions (user_id, stripe_subscription_id, status, current_period_start, current_period_end) VALUES ($1, $2, $3, $4, $5)`, [userId, subscription.id, subscription.status, new Date(subscription.current_period_start * 1000), new Date(subscription.current_period_end * 1000)]);
        break;
      case 'customer.subscription.deleted':
        const deletedSub = event.data.object;
        await pool.query('UPDATE users SET plan = $1 WHERE stripe_customer_id = $2', ['free', deletedSub.customer]);
        await pool.query('UPDATE subscriptions SET status = $1 WHERE stripe_subscription_id = $2', ['canceled', deletedSub.id]);
        break;
    }
    res.json({ received: true });
  } catch (err) {
    console.error('❌ Webhook error:', err);
    res.status(400).send(`Webhook Error: ${err.message}`);
  }
});

app.post('/analyze-email', authenticateSupabaseToken, async (req, res) => {
  try {
    const { emailContent, sender, subject } = req.body;
    if (!emailContent) return res.status(400).json({ error: 'Missing email content' });
    await resetMonthlyCountIfNeeded(req.user.id);
    const usage = await pool.query('SELECT plan, emails_analyzed_this_month FROM users WHERE id = $1', [req.user.id]);
    const monthlyLimit = usage.rows[0].plan === 'free' ? 50 : 10000;
    if (usage.rows[0].emails_analyzed_this_month >= monthlyLimit) return res.status(429).json({ error: 'Monthly limit reached' });
    const emailHash = generateEmailHash(emailContent, sender || '', subject || '');
    const existing = await pool.query('SELECT * FROM email_analyses WHERE email_hash = $1 AND user_id = $2', [emailHash, req.user.id]);
    if (existing.rows.length > 0) return res.json({ ...existing.rows[0], cached: true });

    const prompt = `Analyze this email and return ONLY a valid JSON object with these exact fields:\nSender: ${sender}\nSubject: ${subject}\nContent: ${emailContent}`;
    const response = await anthropic.messages.create({ model: 'claude-3-haiku-20240307', max_tokens: 1000, messages: [{ role: 'user', content: prompt }] });
    const analysis = JSON.parse(response.content[0].text);
    analysis.processed_at = new Date().toISOString();

    await pool.query(`INSERT INTO email_analyses (user_id, email_hash, sender, subject, email_content, urgency, response_pressure, action_type, has_money_request, money_details, ai_confidence, sentiment) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`, [req.user.id, emailHash, sender, subject, emailContent, analysis.urgency, analysis.response_pressure, analysis.action_type, analysis.has_money_request, analysis.money_details, analysis.ai_confidence, analysis.sentiment]);
    await pool.query('UPDATE users SET emails_analyzed_this_month = emails_analyzed_this_month + 1 WHERE id = $1', [req.user.id]);
    res.json(analysis);
  } catch (error) {
    console.error('❌ Analysis error:', error);
    res.status(500).json({ error: 'Failed to analyze email' });
  }
});

app.get('/analyses/history', authenticateSupabaseToken, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;
    const history = await pool.query('SELECT id, sender, subject, urgency, response_pressure, action_type, has_money_request, sentiment, processed_at FROM email_analyses WHERE user_id = $1 ORDER BY processed_at DESC LIMIT $2 OFFSET $3', [req.user.id, limit, offset]);
    const count = await pool.query('SELECT COUNT(*) FROM email_analyses WHERE user_id = $1', [req.user.id]);
    res.json({ analyses: history.rows, total: parseInt(count.rows[0].count), page: parseInt(page), limit: parseInt(limit) });
  } catch (error) {
    console.error('❌ History error:', error);
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

app.get('/usage/stats', authenticateSupabaseToken, async (req, res) => {
  try {
    await resetMonthlyCountIfNeeded(req.user.id);
    const stats = await pool.query('SELECT plan, emails_analyzed_this_month FROM users WHERE id = $1', [req.user.id]);
    const monthlyLimit = stats.rows[0].plan === 'free' ? 50 : 10000;
    res.json({ plan: stats.rows[0].plan, emails_analyzed_this_month: stats.rows[0].emails_analyzed_this_month, monthly_limit: monthlyLimit });
  } catch (error) {
    console.error('❌ Stats error:', error);
    res.status(500).json({ error: 'Failed to fetch usage stats' });
  }
});

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

app.get('/debug/drop-password-constraint', async (req, res) => {
  try {
    await pool.query('ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;');
    res.send('✅ password_hash column is now optional');
  } catch (err) {
    res.status(500).send('❌ Failed: ' + err.message);
  }
});


startServer().catch(console.error);