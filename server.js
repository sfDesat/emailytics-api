// server.js - Complete Email Analysis Backend
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const { Anthropic } = require('@anthropic-ai/sdk');
const stripe = require('stripe');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Initialize services
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const anthropic = new Anthropic({
  apiKey: process.env.CLAUDE_API_KEY
});

const stripeClient = stripe(process.env.STRIPE_SECRET_KEY);

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Auth middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userResult = await pool.query(
      'SELECT id, email, plan, emails_analyzed_this_month FROM users WHERE id = $1',
      [decoded.userId]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    req.user = userResult.rows[0];
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Database initialization
async function initializeDatabase() {
  try {
    // Users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        plan VARCHAR(50) DEFAULT 'free',
        stripe_customer_id VARCHAR(255),
        emails_analyzed_this_month INTEGER DEFAULT 0,
        month_reset_date DATE DEFAULT CURRENT_DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Email analyses table
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

    // Subscriptions table
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

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

// Helper functions
function generateEmailHash(emailContent, sender, subject) {
  const crypto = require('crypto');
  const content = `${emailContent}${sender}${subject}`;
  return crypto.createHash('sha256').update(content).digest('hex');
}

async function resetMonthlyCountIfNeeded(userId) {
  const result = await pool.query(
    'SELECT month_reset_date FROM users WHERE id = $1',
    [userId]
  );
  
  const resetDate = new Date(result.rows[0].month_reset_date);
  const now = new Date();
  
  // Check if it's been a month since last reset
  if (now.getMonth() !== resetDate.getMonth() || now.getFullYear() !== resetDate.getFullYear()) {
    await pool.query(
      'UPDATE users SET emails_analyzed_this_month = 0, month_reset_date = $1 WHERE id = $2',
      [now.toISOString().split('T')[0], userId]
    );
  }
}

// Routes

// Health check
app.get('/', (req, res) => {
  res.json({
    message: 'Email AI Backend is running!',
    timestamp: new Date().toISOString(),
    version: '2.0.0'
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

// User registration
app.post('/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email.toLowerCase()]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Hash password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create Stripe customer
    const stripeCustomer = await stripeClient.customers.create({
      email: email.toLowerCase(),
      metadata: { source: 'email_ai_app' }
    });

    // Create user
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, stripe_customer_id) VALUES ($1, $2, $3) RETURNING id, email, plan',
      [email.toLowerCase(), passwordHash, stripeCustomer.id]
    );

    const user = result.rows[0];

    // Generate JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: { id: user.id, email: user.email, plan: user.plan }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// User login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const result = await pool.query(
      'SELECT id, email, password_hash, plan FROM users WHERE email = $1',
      [email.toLowerCase()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, email: user.email, plan: user.plan }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get user profile
app.get('/auth/profile', authenticateToken, (req, res) => {
  res.json({
    user: {
      id: req.user.id,
      email: req.user.email,
      plan: req.user.plan,
      emails_analyzed_this_month: req.user.emails_analyzed_this_month
    }
  });
});

// Create Stripe checkout session
app.post('/payments/create-checkout-session', authenticateToken, async (req, res) => {
  try {
    const { priceId } = req.body;

    const session = await stripeClient.checkout.sessions.create({
      customer: req.user.stripe_customer_id,
      payment_method_types: ['card'],
      line_items: [
        {
          price: priceId, // You'll create this in Stripe dashboard
          quantity: 1,
        },
      ],
      mode: 'subscription',
      success_url: `${process.env.FRONTEND_URL}/dashboard?success=true`,
      cancel_url: `${process.env.FRONTEND_URL}/pricing?canceled=true`,
      metadata: {
        userId: req.user.id.toString()
      }
    });

    res.json({ sessionId: session.id });
  } catch (error) {
    console.error('Stripe checkout error:', error);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// Stripe webhook handler
app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripeClient.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed':
        const session = event.data.object;
        const userId = session.metadata.userId;
        
        // Update user to paid plan
        await pool.query(
          'UPDATE users SET plan = $1 WHERE id = $2',
          ['paid', userId]
        );
        
        // Create subscription record
        const subscription = await stripeClient.subscriptions.retrieve(session.subscription);
        await pool.query(
          'INSERT INTO subscriptions (user_id, stripe_subscription_id, status, current_period_start, current_period_end) VALUES ($1, $2, $3, $4, $5)',
          [
            userId,
            subscription.id,
            subscription.status,
            new Date(subscription.current_period_start * 1000),
            new Date(subscription.current_period_end * 1000)
          ]
        );
        break;

      case 'customer.subscription.deleted':
        const deletedSub = event.data.object;
        
        // Update user back to free plan
        await pool.query(
          'UPDATE users SET plan = $1 WHERE stripe_customer_id = $2',
          ['free', deletedSub.customer]
        );
        
        // Update subscription status
        await pool.query(
          'UPDATE subscriptions SET status = $1 WHERE stripe_subscription_id = $2',
          ['canceled', deletedSub.id]
        );
        break;
    }

    res.json({ received: true });
  } catch (error) {
    console.error('Webhook handler error:', error);
    res.status(500).json({ error: 'Webhook handler failed' });
  }
});

// Main email analysis endpoint
app.post('/analyze-email', authenticateToken, async (req, res) => {
  try {
    const { emailContent, sender, subject } = req.body;

    if (!emailContent) {
      return res.status(400).json({ error: 'Email content is required' });
    }

    // Reset monthly count if needed
    await resetMonthlyCountIfNeeded(req.user.id);

    // Check usage limits
    const userResult = await pool.query(
      'SELECT plan, emails_analyzed_this_month FROM users WHERE id = $1',
      [req.user.id]
    );
    
    const user = userResult.rows[0];
    const monthlyLimit = user.plan === 'free' ? 50 : 10000; // Generous limit for paid users

    if (user.emails_analyzed_this_month >= monthlyLimit) {
      return res.status(429).json({
        error: 'Monthly limit reached',
        limit: monthlyLimit,
        plan: user.plan
      });
    }

    // Generate email hash to check for duplicates
    const emailHash = generateEmailHash(emailContent, sender || '', subject || '');

    // Check if we've already analyzed this email
    const existingAnalysis = await pool.query(
      'SELECT * FROM email_analyses WHERE email_hash = $1 AND user_id = $2',
      [emailHash, req.user.id]
    );

    if (existingAnalysis.rows.length > 0) {
      const analysis = existingAnalysis.rows[0];
      return res.json({
        ...analysis,
        cached: true,
        processed_at: analysis.processed_at
      });
    }

    // Analyze email with Claude
    const prompt = `Analyze this email and return ONLY a valid JSON object with these exact fields:
- urgency: number from 1-10 (10 = extremely urgent)
- response_pressure: "none", "low", "medium", "high"  
- action_type: "information", "question", "request", "task", "feedback", or "meeting"
- has_money_request: true or false
- money_details: object with amount, due_date, type (null if no money involved)
- ai_confidence: number from 1-10 (how confident are you in your analysis)
- sentiment: "positive", "neutral", "negative", or "mixed"

Email Details:
Sender: ${sender || 'Unknown'}
Subject: ${subject || 'No subject'}
Content: ${emailContent}

Return only the JSON, no other text.`;

    console.log('Sending request to Claude AI...');
    
    const response = await anthropic.messages.create({
      model: "claude-3-haiku-20240307",
      max_tokens: 1000,
      messages: [{
        role: "user",
        content: prompt
      }]
    });

    const analysisText = response.content[0].text;
    console.log('Claude response:', analysisText);
    
    const analysis = JSON.parse(analysisText);
    analysis.processed_at = new Date().toISOString();

    // Save analysis to database
    await pool.query(
      `INSERT INTO email_analyses 
       (user_id, email_hash, sender, subject, email_content, urgency, response_pressure, 
        action_type, has_money_request, money_details, ai_confidence, sentiment) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [
        req.user.id,
        emailHash,
        sender,
        subject,
        emailContent,
        analysis.urgency,
        analysis.response_pressure,
        analysis.action_type,
        analysis.has_money_request,
        analysis.money_details,
        analysis.ai_confidence,
        analysis.sentiment
      ]
    );

    // Increment user's monthly count
    await pool.query(
      'UPDATE users SET emails_analyzed_this_month = emails_analyzed_this_month + 1 WHERE id = $1',
      [req.user.id]
    );

    res.json(analysis);

  } catch (error) {
    console.error('Error analyzing email:', error);
    res.status(500).json({
      error: 'Failed to analyze email',
      details: error.message
    });
  }
});

// Get user's email analysis history
app.get('/analyses/history', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    const result = await pool.query(
      `SELECT id, sender, subject, urgency, response_pressure, action_type, 
              has_money_request, sentiment, processed_at 
       FROM email_analyses 
       WHERE user_id = $1 
       ORDER BY processed_at DESC 
       LIMIT $2 OFFSET $3`,
      [req.user.id, limit, offset]
    );

    const countResult = await pool.query(
      'SELECT COUNT(*) FROM email_analyses WHERE user_id = $1',
      [req.user.id]
    );

    res.json({
      analyses: result.rows,
      total: parseInt(countResult.rows[0].count),
      page: parseInt(page),
      limit: parseInt(limit)
    });

  } catch (error) {
    console.error('Error fetching history:', error);
    res.status(500).json({ error: 'Failed to fetch analysis history' });
  }
});

// Get usage statistics
app.get('/usage/stats', authenticateToken, async (req, res) => {
  try {
    await resetMonthlyCountIfNeeded(req.user.id);
    
    const userResult = await pool.query(
      'SELECT plan, emails_analyzed_this_month FROM users WHERE id = $1',
      [req.user.id]
    );
    
    const user = userResult.rows[0];
    const monthlyLimit = user.plan === 'free' ? 50 : 10000;

    res.json({
      plan: user.plan,
      emails_analyzed_this_month: user.emails_analyzed_this_month,
      monthly_limit: monthlyLimit,
      remaining: monthlyLimit - user.emails_analyzed_this_month
    });

  } catch (error) {
    console.error('Error fetching usage stats:', error);
    res.status(500).json({ error: 'Failed to fetch usage statistics' });
  }
});

// Initialize database and start server
async function startServer() {
  await initializeDatabase();
  
  app.listen(port, () => {
    console.log(`🚀 Server running at http://localhost:${port}`);
    console.log(`📧 Email analysis endpoint: http://localhost:${port}/analyze-email`);
    console.log(`❤️  Health check: http://localhost:${port}/health`);
    console.log(`🔐 Auth endpoints available`);
    console.log(`💳 Payment endpoints available`);
  });
}

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Server is shutting down...');
  pool.end();
  process.exit(0);
});

startServer().catch(console.error);