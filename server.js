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

const app  = express();
const port = process.env.PORT || 3000;
app.set('trust proxy', 1);
app.disable('x-powered-by');

/* ────────── 1. PLAN CONSTANTS ────────── */
const PLAN_FEATURES = {
  free:     ['priority','intent','deadline'],
  standard: ['priority','intent','tasks','sentiment'],
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
const limitUser = (req,res,next)=>
  limiterPerUser.consume(String(req.user.id))
  .then(()=>next())
  .catch(()=>res.status(429).json({ error:'Too many requests' }));

/* ────────── 6. ZOD SCHEMA ────────── */
const analyzeSchema = z.object({
  email_content : z.string().min(10).max(10_000),
  sender        : z.string().max(320),
  subject       : z.string().max(500)
});

// ─── 7. Initialize Tables & Indexes ─────────────────────────
async function initializeDatabase() {
  try {
    /* USERS */
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
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
const authenticate = async (req,res,next)=>{
  const token = req.headers.authorization?.split(' ')[1];
  if(!token) return res.status(401).json({ error:'Token required' });
  try{
    const { data:{user}, error } = await supabase.auth.getUser(token);
    if(error || !user) throw error||new Error('invalid user');

    const { rows:[row] } = await pool.query(
      `INSERT INTO users (email) VALUES ($1)
       ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
       RETURNING *`, [user.email]);

    req.user = row;
    next();
  }catch(e){
    console.error('Auth error:',e);
    res.status(403).json({ error:'Invalid or expired token' });
  }
};

/* ────────── 8. ROUTES ────────── */
app.get('/',(_,res)=>res.json({ status:'ok', ts:new Date().toISOString() }));

app.get('/auth/profile', authenticate, (req,res)=>{
  res.json({
    id:req.user.id,
    email:req.user.email,
    plan:req.user.plan,
    features:PLAN_FEATURES[(req.user.plan||'free').toLowerCase()]||[]
  });
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
    if(!parsed.success) return res.status(400).json({ error:'Bad payload' });
    req.body = parsed.data; next();
  },
  async (req,res,next)=>{
    try{
      const { email_content, sender, subject } = req.body;
      const plan = (req.user.plan||'free').toLowerCase();

      if(req.user.emails_analyzed_this_month >= PLAN_LIMITS[plan])
        return res.status(403).json({ error:'Monthly limit reached' });

      /* hash uses subject but we never store it */
      const hash = require('crypto').createHash('sha256')
                   .update(email_content+sender+subject).digest('hex');

      const { rows:[cached] } = await pool.query(
        'SELECT * FROM email_analyses WHERE email_hash=$1 AND user_id=$2',
        [hash, req.user.id]);

      const needsReanalyse = cached && cached.plan_at_analysis==='free' && plan!=='free';
      if(cached && !needsReanalyse){
        const allowed = PLAN_FEATURES[plan];
        return res.json(allowed.reduce((o,k)=>(o[k]=cached[k],o),{}));
      }

      /* Claude call */
      const prompt = buildClaudePrompt({
        sender, subject, emailContent: email_content, fields: PLAN_FEATURES[plan]
      });
      const { content:[{text}] } = await anthropic.messages.create({
        model:'claude-3-haiku-20240307',
        max_tokens:1300, temperature:0.5,
        messages:[{ role:'user', content:prompt }]
      });
      const parsed = JSON.parse(text);
      if(['null','',null].includes(parsed.deadline)) parsed.deadline = null;

      console.log('🧠 Claude raw response:', text);

      /* UPSERT (no subject column) */
      let confidence = parsed.ai_confidence;
      if (typeof confidence !== 'number') confidence = parseFloat(confidence);
      if (isNaN(confidence)) confidence = null;
      else confidence = Math.round(confidence);
          
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
        [
          req.user.id, hash,
          parsed.priority||null,
          parsed.intent||null,
          parsed.tone||null,
          parsed.sentiment||null,
          parsed.tasks||null,
          parsed.deadline||null,
          confidence,
          plan
        ]);

      /* usage counters */
      await pool.query(`
        UPDATE users SET
          emails_analyzed_this_month = emails_analyzed_this_month + 1,
          total_emails_ever         = total_emails_ever + 1
        WHERE id=$1`, [req.user.id]);

      const allowed = PLAN_FEATURES[plan];
      res.json(allowed.reduce((o,k)=>(o[k]=row[k],o),{}));
    }catch(e){ next(e); }
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

/* ────────── 9. ERROR HANDLER ────────── */
app.use((err,req,res,_next)=>{
  console.error('Unhandled error →',err);
  res.status(500).json({ error:'Internal server error' });
});

/* ────────── 10. BOOTSTRAP ────────── */
initializeDatabase().then(()=>{
  app.listen(port,()=>console.log(`🚀 Server ready on ${port}`)); 
});