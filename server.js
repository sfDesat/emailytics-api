// server.js – Secure Emailytics backend (MVP)


/* ────────── 0. IMPORTS & INIT ────────── */
const express  = require('express');
const cors     = require('cors');
const helmet   = require('helmet');
const { Pool } = require('pg');
const rateLimitIP          = require('express-rate-limit');
const { RateLimiterMemory} = require('rate-limiter-flexible');
const { z }    = require('zod');
const stripe   = require('stripe');
const { Anthropic } = require('@anthropic-ai/sdk');
const { createClient } = require('@supabase/supabase-js');
const buildClaudePrompt = require('./utils/claudePrompt');
require('dotenv').config();

/* ─── helpers ─────────────────────────────────────────── */
const makeHash = (sender = 'Unknown',
                  subject = '(No Subject)',
                  time = '') =>
  require('crypto')
    .createHash('sha256')
    .update(`${sender}|${subject}|${time}`)
    .digest('hex');

const roughTokenCount = str => Math.ceil(str.length / 4);  // fast upper-bound
const roughTrim       = (str,maxTok=1500)=>
  roughTokenCount(str)<=maxTok?str:str.slice(0,maxTok*4);

/* ─── express boilerplate ─────────────────────────────── */
const app  = express();
const port = process.env.PORT || 3000;
app.set('trust proxy', 1);
app.disable('x-powered-by');

/* ────────── 1. PLAN CONSTANTS ────────── */
const PLAN_FEATURES = {
  free:     ['priority','intent','deadline'],
  standard: ['priority','intent','tasks','sentiment','deadline'],
  pro:      ['priority','intent','tasks','sentiment','tone','deadline','ai_confidence']
};
const PLAN_LIMITS = { free: 100, standard: 600, pro: Infinity };

/* ────────── 2. DATABASE ────────── */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized:false } : false,
  max: 10
});

/* ────────── 3. 3RD-PARTY CLIENTS ────────── */
const supabase     = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
const stripeClient = stripe(process.env.STRIPE_SECRET_KEY);
const stripeSecret = process.env.STRIPE_WEBHOOK_SECRET;
const anthropic    = new Anthropic({ apiKey: process.env.CLAUDE_API_KEY });

/* ────────── 4. MIDDLEWARE ────────── */
app.use('/webhooks/stripe', express.raw({ type:'application/json' }));
app.use(helmet({
  crossOriginResourcePolicy:{ policy:'same-site' },
  referrerPolicy:{ policy:'no-referrer' }
}));
app.use(cors({
  origin:['https://mail.google.com', process.env.FRONTEND_URL],
  credentials:true
}));
app.use(rateLimitIP({ windowMs:15*60*1000, max:100 }));
app.use(express.json({ limit:'10mb' }));

/* ────────── 5. PER-USER RATE-LIMIT ────────── */
const limiterPerUser = new RateLimiterMemory({ points:30, duration:60 });
const limitUser = (req,res,next)=>limiterPerUser
  .consume(String(req.user.id)).then(()=>next())
  .catch(()=>res.status(429).json({ error:'Too many requests' }));

/* ────────── 6. ZOD SCHEMA ────────── */
const analyzeSchema = z.object({
  email_content : z.string().min(0).max(10_000),
  sender        : z.string().max(320),
  subject       : z.string().max(500),
  time          : z.string().min(1, "time is required")
});

// ─── 7. Initialize Tables & Indexes ─────────────────────────
async function initializeDatabase() {
  try {
    /* USERS */
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        consent_given BOOLEAN DEFAULT FALSE,
        plan  VARCHAR(50)  DEFAULT 'Free',
        stripe_customer_id VARCHAR(255),
        emails_analyzed_this_month INTEGER DEFAULT 0,
        total_emails_ever INTEGER DEFAULT 0,
        month_reset_date DATE DEFAULT CURRENT_DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`);

    /* EMAIL_ANALYSES – no subject column */
    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_analyses (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        plan_at_analysis VARCHAR(50),
        email_hash VARCHAR(64) NOT NULL,
        priority VARCHAR(50),
        intent TEXT,
        tone VARCHAR(50),
        sentiment VARCHAR(50),
        tasks TEXT[],
        deadline DATE,
        ai_confidence INTEGER,
        processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(email_hash,user_id)
      )`);

    /* ★ Clean-up deployments that still have "subject" */
    await pool.query(`ALTER TABLE email_analyses DROP COLUMN IF EXISTS subject`);

    /* SUBSCRIPTIONS */
    await pool.query(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        stripe_subscription_id VARCHAR(255) UNIQUE NOT NULL,
        status VARCHAR(50) NOT NULL,
        current_period_start TIMESTAMP,
        current_period_end   TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`);

    /* Secondary indexes */
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_email             ON users(email)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_email_analyses_hash     ON email_analyses(email_hash)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe_id ON subscriptions(stripe_subscription_id)`);

    console.log('✅ Database & indexes initialized');
  } catch (err) {
    console.error('❌ DB init error:', err);
  }
}

/* ────────── 8. AUTH MIDDLEWARE ────────── */
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });

  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) throw error || new Error('invalid user');

    /* our own Postgres users table (numeric id) */
    const { rows: [row] } = await pool.query(
      `INSERT INTO users (email)
         VALUES ($1)
      ON CONFLICT (email)
      DO UPDATE SET email = EXCLUDED.email
      RETURNING *`,
      [user.email]
    );

    req.user     = row;      // internal row (numeric id)
    req.authUuid = user.id;  // **Supabase Auth UUID** – needed for delete

    next();
  } catch (e) {
    console.error('Auth error:', e);
    res.status(403).json({ error: 'Invalid or expired token' });
  }
};

/* ────────── 9. ROUTES ────────── */
app.get('/',(_,res)=>res.json({ status:'ok', ts:new Date().toISOString() }));

app.post('/auth/consent', authenticate, async (req, res, next) => {
  try {
    await pool.query(
      'UPDATE users SET consent_given = true, updated_at = NOW() WHERE id = $1',
      [req.user.id]
    );
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.get('/auth/profile', authenticate, (req,res)=>{
  res.json({
    id:req.user.id,
    email:req.user.email,
    plan:req.user.plan,
    features:PLAN_FEATURES[(req.user.plan||'free').toLowerCase()]||[]
  });
});

app.get('/gdpr/data', authenticate, async (req, res, next) => {
  try {
    const { rows: analyses } = await pool.query(
      `SELECT priority,intent,tone,sentiment,tasks,deadline,
              ai_confidence,processed_at
         FROM email_analyses
        WHERE user_id = $1
        ORDER BY processed_at DESC`,
      [req.user.id]
    );

    res.setHeader('Content-Type', 'application/json');
    res.setHeader(
      'Content-Disposition',
      'attachment; filename="emailytics-data.json"'
    );
    res.json({
      user: {
        id: req.user.id,
        email: req.user.email,
        plan: req.user.plan,
        created_at: req.user.created_at,
      },
      analyses,
    });
  } catch (e) {
    next(e);
  }
});

app.delete('/gdpr/data', authenticate, async (req, res, next) => {
  try {
    /* wipe Postgres data */
    await pool.query('DELETE FROM email_analyses WHERE user_id = $1', [req.user.id]);
    await pool.query('DELETE FROM subscriptions  WHERE user_id = $1', [req.user.id]);
    await pool.query('DELETE FROM users         WHERE id      = $1', [req.user.id]);

    /* wipe Supabase Auth record – MUST use the UUID */
    await supabase.auth.admin.deleteUser(req.authUuid);

    res.json({ deleted: true });
  } catch (e) {
    next(e);
  }
});

app.get('/dashboard', authenticate, async (req,res,next)=>{
  try{
    const u=req.user, plan=(u.plan||'free').toLowerCase(), limit=PLAN_LIMITS[plan];
    const { rows:[sub] } = await pool.query(
      'SELECT status FROM subscriptions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1',[u.id]);
    res.json({
      email:u.email,
      plan:u.plan,
      emailsAnalyzedThisMonth:u.emails_analyzed_this_month,
      totalEmailsAnalyzed:u.total_emails_ever,
      monthlyLimit: limit===Infinity?null:limit,
      nextResetDate:u.month_reset_date?.toISOString().split('T')[0]||null,
      subscriptionStatus:sub?.status||'none',
      features:PLAN_FEATURES[plan]
    });
  }catch(e){ next(e); }
});

app.post('/analyze',
  authenticate,
  limitUser,
  (req,res,next)=>{
    const parsed = analyzeSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error:'Bad payload' });
    req.body = parsed.data; next();
  },
  async (req,res,next)=>{
    try{
      let { email_content, sender, subject, time } = req.body;
          
      // guard: we only process when the Gmail tooltip produced a real timestamp
      if (!time || time === "0" || time.toLowerCase?.() === "unknown") {
        return res.status(400).json({ error: "Missing or invalid time field" });
      }
      
      sender  ||= 'Unknown';
      subject ||= '(No Subject)';
      const plan = (req.user.plan||'free').toLowerCase();

      email_content = roughTrim(email_content,1500);
      const emailHash = makeHash(sender,subject,time);

      /* empty mail → cheap fallback */
      if (email_content.trim().length < 10) {
        const fallback = {
          priority:'Low', intent:'Message is empty',
          tone:null,sentiment:null,tasks:[],deadline:null,ai_confidence:0
        };

        await pool.query(`
          INSERT INTO email_analyses (
            user_id,email_hash,priority,intent,tone,sentiment,
            tasks,deadline,ai_confidence,plan_at_analysis
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
          ON CONFLICT (email_hash,user_id) DO NOTHING`,
          [req.user.id,emailHash,
           fallback.priority,fallback.intent,fallback.tone,fallback.sentiment,
           fallback.tasks,fallback.deadline,fallback.ai_confidence,plan]);

        await pool.query(`
          UPDATE users SET
            emails_analyzed_this_month = emails_analyzed_this_month + 1,
            total_emails_ever          = total_emails_ever + 1
          WHERE id=$1`,[req.user.id]);

        const allowed = PLAN_FEATURES[plan];
        return res.json(allowed.reduce((o,k)=>(o[k]=fallback[k],o),{}));
      }

      /* consent / quota */
      if (!req.user.consent_given)
        return res.status(403).json({ error:'Consent required' });
      if (req.user.emails_analyzed_this_month >= PLAN_LIMITS[plan])
        return res.status(403).json({ error:'Monthly limit reached' });

      /* cache hit? */
      const { rows:[cached] } = await pool.query(
        'SELECT * FROM email_analyses WHERE email_hash=$1 AND user_id=$2',
        [emailHash,req.user.id]);
      const needsUpgrade = cached && cached.plan_at_analysis==='free' && plan!=='free';
      if (cached && !needsUpgrade) {
        const allowed = PLAN_FEATURES[plan];
        return res.json(allowed.reduce((o,k)=>(o[k]=cached[k],o),{}));
      }

      /* call Claude */
      const prompt = buildClaudePrompt({
        sender, subject, emailContent:email_content, fields:PLAN_FEATURES[plan]
      });
      const { content:[{ text }] } = await anthropic.messages.create({
        model:'claude-3-haiku-20240307',
        max_tokens:1500, temperature:0.5,
        messages:[{ role:'user', content:prompt }]
      });
      const parsed = JSON.parse(text);
      if(['null','',null].includes(parsed.deadline)) parsed.deadline = null;

      /* confidence normalisation */
      let confidence = parsed.ai_confidence;
      if (typeof confidence!=='number') confidence=parseFloat(confidence);
      if (Number.isNaN(confidence)) confidence=null;
      if (confidence!=null) confidence=Math.round(confidence);

      const { rows:[row] } = await pool.query(`
        INSERT INTO email_analyses (
          user_id,email_hash,priority,intent,tone,sentiment,
          tasks,deadline,ai_confidence,plan_at_analysis
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        ON CONFLICT (email_hash,user_id) DO UPDATE
          SET priority         = EXCLUDED.priority,
              intent           = EXCLUDED.intent,
              tone             = EXCLUDED.tone,
              sentiment        = EXCLUDED.sentiment,
              tasks            = EXCLUDED.tasks,
              deadline         = EXCLUDED.deadline,
              ai_confidence    = EXCLUDED.ai_confidence,
              plan_at_analysis = EXCLUDED.plan_at_analysis
        RETURNING *`,
        [req.user.id,emailHash,
         parsed.priority||null,parsed.intent||null,parsed.tone||null,
         parsed.sentiment||null,parsed.tasks||null,parsed.deadline||null,
         confidence,plan]);

      await pool.query(`
        UPDATE users SET
          emails_analyzed_this_month = emails_analyzed_this_month + 1,
          total_emails_ever          = total_emails_ever + 1
        WHERE id=$1`,[req.user.id]);

      const allowed = PLAN_FEATURES[plan];
      res.json(allowed.reduce((o,k)=>(o[k]=row[k],o),{}));
    }catch(err){ next(err); }
});

/* ---- STRIPE WEBHOOK (POST only) ---- */
app.post('/webhooks/stripe',(req,res)=>{
  const sig=req.headers['stripe-signature'];
  let event;
  try{ event = stripeClient.webhooks.constructEvent(req.body,sig,stripeSecret); }
  catch(err){ return res.status(400).send(`Webhook Error: ${err.message}`); }

  switch(event.type){
    case 'invoice.payment_succeeded':   /* TODO */ break;
    case 'customer.subscription.deleted': /* TODO */ break;
    default: console.log('Stripe event:',event.type);
  }
  res.json({received:true});
});

/* ────────── 10. ERROR HANDLER ────────── */
app.use((err,req,res,_next)=>{
  console.error('Unhandled error →',err);
  res.status(500).json({ error:'Internal server error' });
});

/* ────────── 11. BOOTSTRAP ────────── */
initializeDatabase().then(()=>{
  app.listen(port,()=>console.log(`🚀 Server ready on ${port}`)); 
});