// server.js – Supabase Integrated Email Analysis Backend with Plan Limits, Cron Reset, Upserts & Indexes


/* ────────── 0. IMPORTS & INIT ────────── */
const express     = require('express');
const cors        = require('cors');
const { Pool }    = require('pg');
const rateLimit   = require('express-rate-limit');
const { Anthropic }   = require('@anthropic-ai/sdk');
const stripe      = require('stripe');
const { createClient } = require('@supabase/supabase-js');
const buildClaudePrompt = require('./utils/claudePrompt');
const helmet      = require('helmet');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
app.set('trust proxy', 1);

/* ────────── 1. CONSTANTS ────────── */
const PLAN_FEATURES = {
  free:     ['priority','intent','deadline'],
  standard: ['priority','intent','tasks','sentiment'],
  pro:      ['priority','intent','tasks','sentiment','tone','deadline','ai_confidence']
};
const PLAN_LIMITS = { free: 100, standard: 600, pro: Infinity };

/* ────────── 2. DATABASE ────────── */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: false }
        : false,
  max: 10
});

/* ────────── 3. 3RD-PARTY CLIENTS ────────── */
const supabase      = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
const stripeClient  = stripe(process.env.STRIPE_SECRET_KEY);
const stripeSecret  = process.env.STRIPE_WEBHOOK_SECRET;          // ← for signature check
const anthropic     = new Anthropic({ apiKey: process.env.CLAUDE_API_KEY });

/* ────────── 4. MIDDLEWARE ────────── */
app.use('/webhooks/stripe', express.raw({ type: 'application/json' })); // raw body for Stripe
app.use(helmet()); // Security headers
app.use(cors({
  origin: ['https://mail.google.com', process.env.FRONTEND_URL],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// ─── Initialize Tables & Indexes ─────────────────────────
async function initializeDatabase() {
  try {
    // Users
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
    // Email Analyses
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
    // Subscriptions
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

    // Indexes
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_email_analyses_hash ON email_analyses(email_hash)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe_id ON subscriptions(stripe_subscription_id)`);

    console.log('✅ Database & indexes initialized');
  } catch (err) {
    console.error('❌ DB init error:', err);
  }
}

// ─── Auth Middleware ──────────────────────────────────────
const authenticateSupabaseToken = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });

  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) throw error || new Error('Invalid user');

    let result = await pool.query('SELECT * FROM users WHERE email = $1', [user.email]);
    let row = result.rows[0];
    if (!row) {
      const insert = await pool.query(
        'INSERT INTO users (email) VALUES ($1) RETURNING *',
        [user.email]
      );
      row = insert.rows[0];
    }
    req.user = row;
    next();
  } catch (err) {
    console.error('❌ Auth error:', err);
    res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// ─── Routes ───────────────────────────────────────────────
// Healthcheck
app.get('/',              (_,res)=>res.json({status:'ok',ts:new Date().toISOString()}));

// Profile
app.get('/auth/profile',  authenticateSupabaseToken, (req,res)=>res.json({user:req.user}));

// Dashboard
app.get('/dashboard', authenticateSupabaseToken, async (req, res) => {
  try {
    const user = req.user;
    const plan = user.plan?.toLowerCase() || 'free';
    const limit = PLAN_LIMITS[plan];
    const isUnlimited = limit === Infinity;

    // Use tracked total_emails_ever
    res.json({
      email: user.email,
      plan: user.plan,
      emailsAnalyzedThisMonth: user.emails_analyzed_this_month,
      totalEmailsAnalyzed: user.total_emails_ever,
      monthlyLimit: isUnlimited ? null : limit,
      nextResetDate: user.month_reset_date?.toISOString().split('T')[0] || null,
      subscriptionStatus: await (async () => {
        const { rows } = await pool.query(
          'SELECT status FROM subscriptions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1',
          [user.id]
        );
        return rows[0]?.status || 'none';
      })(),
      features: PLAN_FEATURES[plan] || []
    });
  } catch (err) {
    console.error('❌ Dashboard error:', err);
    res.status(500).json({ error: 'Failed to load dashboard' });
  }
});

// Analyze
app.post('/analyze', authenticateSupabaseToken, async (req,res)=>{
  try{
    const { email_content, sender, subject } = req.body;
    const plan = (req.user.plan||'free').toLowerCase();

    /* monthly limit */
    if (req.user.emails_analyzed_this_month >= PLAN_LIMITS[plan])
      return res.status(403).json({ error:'Monthly email analysis limit reached' });

    /* deterministic hash of email */
    const emailHash = require('crypto')
      .createHash('sha256')
      .update(email_content+sender+subject)
      .digest('hex');

    /* ❸  User-scoped cache lookup  */
    const { rows:[existing] } = await pool.query(
      `SELECT * FROM email_analyses
         WHERE email_hash=$1 AND user_id=$2`,           // ← user_id filter
      [emailHash, req.user.id]
    );

    const needsReanalysis = existing
      && existing.plan_at_analysis==='free'
      && plan!=='free';

    if (existing && !needsReanalysis){
      const allowed = PLAN_FEATURES[plan];
      return res.json(allowed.reduce((o,k)=>(o[k]=existing[k],o),{}));
    }

    /* call Claude */
    const prompt = buildClaudePrompt({
      sender, subject, emailContent: email_content, fields: PLAN_FEATURES[plan]
    });
    const { content:[{text}] } = await anthropic.messages.create({
      model:'claude-3-haiku-20240307', max_tokens:1300, temperature:0.5,
      messages:[{role:'user',content:prompt}]
    });
    const parsed = JSON.parse(text);
    if (['null','','null'].includes(parsed.deadline)) parsed.deadline = null;

    /* upsert */
    const { rows:[row] } = await pool.query(`
      INSERT INTO email_analyses (
        user_id,email_hash,subject,priority,intent,tone,sentiment,
        tasks,deadline,ai_confidence,plan_at_analysis
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      ON CONFLICT (email_hash,user_id) DO UPDATE           -- primary key now (hash,user)
        SET priority        = EXCLUDED.priority,
            intent          = EXCLUDED.intent,
            tone            = EXCLUDED.tone,
            sentiment       = EXCLUDED.sentiment,
            tasks           = EXCLUDED.tasks,
            deadline        = EXCLUDED.deadline,
            ai_confidence   = EXCLUDED.ai_confidence,
            plan_at_analysis= EXCLUDED.plan_at_analysis
      RETURNING *`,
      [
        req.user.id,emailHash,subject,
        parsed.priority||null,parsed.intent||null,parsed.tone||null,
        parsed.sentiment||null,parsed.tasks||null,parsed.deadline||null,
        parsed.confidence||null,plan
      ]
    );

    /* counters */
    await pool.query(`
      UPDATE users
         SET emails_analyzed_this_month = emails_analyzed_this_month + 1,
             total_emails_ever         = total_emails_ever + 1
       WHERE id=$1`, [req.user.id]);

    /* filter fields */
    const allowed = PLAN_FEATURES[plan];
    res.json(allowed.reduce((o,k)=>(o[k]=row[k==='confidence'?'ai_confidence':k],o),{}));
  }
  catch(err){
    console.error('❌ Analyze error',err);
    res.status(500).json({ error:'Failed to analyze email' });
  }
});

/* -------- Stripe webhook: signature-verified -------- */
app.post('/webhooks/stripe', (req,res)=>{
  const sig = req.headers['stripe-signature'];
  let event;
  try{
    event = stripeClient.webhooks.constructEvent(req.body, sig, stripeSecret);
  }catch(err){
    console.error('❌ Bad Stripe signature', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  switch(event.type){
    case 'invoice.payment_succeeded':
      // TODO: mark subscription paid
      break;
    case 'customer.subscription.deleted':
      // TODO: downgrade user’s plan
      break;
    default:
      console.log('ℹ️ Unhandled event', event.type);
  }
  res.json({received:true});
});

initializeDatabase().then(() => {
  app.listen(port, () => console.log(`🚀 Server ready on port ${port}`));
});
