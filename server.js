// server.js - Supabase Integrated Email Analysis Backend with Plan Limits and Webhooks
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const { Anthropic } = require('@anthropic-ai/sdk');
const stripe = require('stripe');
const { createClient } = require('@supabase/supabase-js');
const buildClaudePrompt = require('./utils/claudePrompt');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
app.set('trust proxy', 1);

app.use('/webhooks/stripe', express.raw({ type: 'application/json' }));

const PLAN_FEATURES = {
  free: ['priority', 'intent', 'deadline'],
  standard: ['priority', 'intent', 'tasks', 'sentiment'],
  pro: ['priority', 'intent', 'tasks', 'sentiment', 'tone', 'deadline', 'ai_confidence']
};

const PLAN_LIMITS = {
  free: 100,
  standard: 600,
  pro: Infinity
};

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
const stripeClient = stripe(process.env.STRIPE_SECRET_KEY);
const anthropic = new Anthropic({ apiKey: process.env.CLAUDE_API_KEY });

app.use(cors({
  origin: [
    'https://mail.google.com',
    process.env.FRONTEND_URL
  ],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        plan VARCHAR(50) DEFAULT 'Free',
        stripe_customer_id VARCHAR(255),
        emails_analyzed_this_month INTEGER DEFAULT 0,
        total_emails_ever INTEGER DEFAULT 0,
        month_reset_date DATE DEFAULT CURRENT_DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_analyses (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        plan_at_analysis VARCHAR(50),
        email_hash VARCHAR(64) UNIQUE NOT NULL,
        subject TEXT,
        priority VARCHAR(50),
        intent TEXT,
        tone VARCHAR(50),
        sentiment VARCHAR(50),
        tasks TEXT[],
        deadline DATE,
        ai_confidence INTEGER,
        processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        stripe_subscription_id VARCHAR(255) UNIQUE NOT NULL,
        status VARCHAR(50) NOT NULL,
        current_period_start TIMESTAMP,
        current_period_end TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`);

    console.log('✅ Database initialized');
  } catch (err) {
    console.error('❌ DB init error:', err);
  }
}

const authenticateSupabaseToken = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });

  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) throw new Error('Invalid user');
    console.log('🔐 Authenticated user:', user.email);

    let result = await pool.query('SELECT * FROM users WHERE email = $1', [user.email]);
    if (result.rows.length === 0) {
      result = await pool.query('INSERT INTO users (email) VALUES ($1) RETURNING *', [user.email]);
    }
    req.user = result.rows[0];
    next();
  } catch (err) {
    console.error('❌ Supabase auth error:', err);
    res.status(403).json({ error: 'Invalid or expired token' });
  }
};

async function resetMonthlyCountIfNeeded(userId) {
  const result = await pool.query('SELECT month_reset_date FROM users WHERE id = $1', [userId]);
  const resetDate = new Date(result.rows[0].month_reset_date);
  const now = new Date();
  if (now.getMonth() !== resetDate.getMonth() || now.getFullYear() !== resetDate.getFullYear()) {
    await pool.query('UPDATE users SET emails_analyzed_this_month = 0, month_reset_date = $1 WHERE id = $2', [now.toISOString().split('T')[0], userId]);
  }
}

function generateEmailHash(content, sender, subject) {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(content + sender + subject).digest('hex');
}

function enforcePlanLimit(user) {
  const limit = PLAN_LIMITS[user.plan] || PLAN_LIMITS.Free;
  if (user.emails_analyzed_this_month >= limit) {
    throw new Error(`Monthly email analysis limit reached for plan: ${user.plan}`);
  }
}

app.get('/', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/auth/profile', authenticateSupabaseToken, (req, res) => {
  res.json({ user: req.user });
});

app.get('/dashboard', authenticateSupabaseToken, async (req, res) => {
  try {
    const user = req.user;
    const plan = user.plan || 'Free';
    const limit = PLAN_LIMITS[plan];
    const isUnlimited = limit === Infinity;
      
    const { rows: totalEmails } = await pool.query(
      'SELECT COUNT(*) FROM email_analyses WHERE user_id = $1',
      [user.id]
    );

    const { rows: [subscription] } = await pool.query(
      'SELECT * FROM subscriptions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1',
      [user.id]
    );

    res.json({
      email: user.email,
      plan: user.plan,
      emailsAnalyzedThisMonth: user.emails_analyzed_this_month,
      totalEmailsAnalyzed: user.total_emails_ever ?? parseInt(totalEmails[0].count, 10),
      monthlyLimit: isUnlimited ? null : limit,
      nextResetDate: user.month_reset_date ? new Date(user.month_reset_date).toISOString().split('T')[0] : null,
      subscriptionStatus: subscription?.status || 'none',
      currentPeriodEnd: subscription?.current_period_end || null
    });
  } catch (err) {
    console.error('❌ Dashboard fetch error:', err);
    res.status(500).json({ error: 'Failed to load dashboard' });
  }
});

app.get('/extension-check', authenticateSupabaseToken, (req, res) => {
  res.json({ installed: true });
});

app.delete('/delete-account', authenticateSupabaseToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.user.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('❌ Account deletion error:', err);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

app.post('/analyze', authenticateSupabaseToken, async (req, res) => {
  try {
    const { email_content, sender, subject } = req.body;
    await resetMonthlyCountIfNeeded(req.user.id);
    enforcePlanLimit(req.user);

    const emailHash = generateEmailHash(email_content, sender, subject);
    const plan = (req.user.plan || 'free').toLowerCase();

    const existing = await pool.query('SELECT * FROM email_analyses WHERE email_hash = $1', [emailHash]);
    const row = existing.rows[0];

    const needsReanalysis = row && row.plan_at_analysis?.toLowerCase() === 'free' && plan.toLowerCase() !== 'free';

    // ✅ Return cached result with fields filtered to current plan
    if (row && !needsReanalysis) {
      const allowed = PLAN_FEATURES[plan] || PLAN_FEATURES.Free;
      const parsed = {
        ...(allowed.includes('priority') && { priority: row.priority }),
        ...(allowed.includes('intent') && { intent: row.intent }),
        ...(allowed.includes('tasks') && { tasks: row.tasks }),
        ...(allowed.includes('sentiment') && { sentiment: row.sentiment }),
        ...(allowed.includes('tone') && { tone: row.tone }),
        ...(allowed.includes('deadline') && { deadline: row.deadline }),
        ...(allowed.includes('ai_confidence') && { ai_confidence: row.ai_confidence })
      };
      return res.json(parsed);
    }

    const prompt = buildClaudePrompt({ sender, subject, emailContent: email_content, plan });
    const completion = await anthropic.messages.create({
      model: 'claude-3-haiku-20240307',
      max_tokens: 1300,
      temperature: 0.5,
      messages: [{ role: 'user', content: prompt }]
    });

    const fullParsed = JSON.parse(completion.content[0].text);
    fullParsed.deadline = fullParsed.deadline === "null" || !fullParsed.deadline ? null : fullParsed.deadline;

    if (row && needsReanalysis) {
      await pool.query(`
        UPDATE email_analyses SET
          priority = $1, intent = $2, tone = $3, sentiment = $4,
          tasks = $5, deadline = $6, ai_confidence = $7,
          plan_at_analysis = $8
        WHERE email_hash = $9`,
        [
          fullParsed.priority ?? null,
          fullParsed.intent ?? null,
          fullParsed.tone ?? null,
          fullParsed.sentiment ?? null,
          fullParsed.tasks ?? null,
          fullParsed.deadline ?? null,
          fullParsed.confidence ?? null,
          plan,
          emailHash
        ]
      );
    } else {
      await pool.query(`
        INSERT INTO email_analyses (
          user_id, email_hash, subject, priority, intent, tone,
          sentiment, tasks, deadline, ai_confidence, plan_at_analysis
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [
          req.user.id,
          emailHash,
          subject,
          fullParsed.priority ?? null,
          fullParsed.intent ?? null,
          fullParsed.tone ?? null,
          fullParsed.sentiment ?? null,
          fullParsed.tasks ?? null,
          fullParsed.deadline ?? null,
          fullParsed.confidence ?? null,
          plan
        ]
      );
    }

    const allowed = PLAN_FEATURES[plan] || PLAN_FEATURES.Free;
    const parsed = {
      ...(allowed.includes('priority') && { priority: fullParsed.priority }),
      ...(allowed.includes('intent') && { intent: fullParsed.intent }),
      ...(allowed.includes('tasks') && { tasks: fullParsed.tasks }),
      ...(allowed.includes('sentiment') && { sentiment: fullParsed.sentiment }),
      ...(allowed.includes('tone') && { tone: fullParsed.tone }),
      ...(allowed.includes('deadline') && { deadline: fullParsed.deadline }),
      ...(allowed.includes('ai_confidence') && { ai_confidence: fullParsed.confidence })
    };

    await pool.query(`
      UPDATE users
      SET emails_analyzed_this_month = emails_analyzed_this_month + 1,
          total_emails_ever = total_emails_ever + 1
      WHERE id = $1`, [req.user.id]);

    res.json(parsed);
  } catch (err) {
    console.error('❌ Analyze error:', err);
    res.status(500).json({ error: 'Failed to analyze email' });
  }
});

app.post('/webhooks/stripe', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  try {
    const event = stripeClient.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const email = session.customer_email;
      const subscription = await stripeClient.subscriptions.retrieve(session.subscription);
      const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      const user = result.rows[0];

      await pool.query('UPDATE users SET plan = $1, stripe_customer_id = $2 WHERE id = $3', [
        'Standard', subscription.customer, user.id
      ]);

      await pool.query(`INSERT INTO subscriptions (user_id, stripe_subscription_id, status, current_period_start, current_period_end)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (stripe_subscription_id) DO UPDATE SET status = EXCLUDED.status, current_period_start = EXCLUDED.current_period_start, current_period_end = EXCLUDED.current_period_end`,
        [user.id, subscription.id, subscription.status, new Date(subscription.current_period_start * 1000), new Date(subscription.current_period_end * 1000)]
      );
    }

    // 🔄 Handle subscription deletion
    if (event.type === 'customer.subscription.deleted') {
      const subscription = event.data.object;
      await pool.query('UPDATE users SET plan = $1 WHERE stripe_customer_id = $2', ['Free', subscription.customer]);
      await pool.query('UPDATE subscriptions SET status = $1 WHERE stripe_subscription_id = $2', ['cancelled', subscription.id]);
    }

    // 🔁 Handle subscription status updates
    if (event.type === 'customer.subscription.updated') {
      const subscription = event.data.object;
      await pool.query('UPDATE subscriptions SET status = $1, current_period_start = $2, current_period_end = $3 WHERE stripe_subscription_id = $4', [
        subscription.status,
        new Date(subscription.current_period_start * 1000),
        new Date(subscription.current_period_end * 1000),
        subscription.id
      ]);
    }

    // ❌ Handle payment failure (auto-downgrade)
    if (event.type === 'invoice.payment_failed') {
      const invoice = event.data.object;
      const subscription = await stripeClient.subscriptions.retrieve(invoice.subscription);
      await pool.query('UPDATE users SET plan = $1 WHERE stripe_customer_id = $2', ['Free', subscription.customer]);
      await pool.query('UPDATE subscriptions SET status = $1 WHERE stripe_subscription_id = $2', ['payment_failed', subscription.id]);
    }

    // 🧹 Handle deleted customers (cleanup user and data)
    if (event.type === 'customer.deleted') {
      const customer = event.data.object;
      await pool.query('DELETE FROM users WHERE stripe_customer_id = $1', [customer.id]);
    }

    res.json({ received: true });
  } catch (err) {
    console.error('❌ Stripe webhook error:', err);
    res.status(400).send(`Webhook Error: ${err.message}`);
  }
});

initializeDatabase().then(() => {
  app.listen(port, () => console.log(`🚀 Server ready at http://localhost:${port}`));
});

process.on('SIGINT', () => {
  console.log('🔻 Shutting down');
  pool.end(() => process.exit(0));
});