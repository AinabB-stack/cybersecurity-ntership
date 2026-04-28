/**
 * =============================================================
 * CYBERSECURITY INTERNSHIP PROJECT - Weeks 4-6
 * Secure Express.js Application
 * =============================================================
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

// ============================================================
// WEEK 4 - TASK 1: LOGGING & MONITORING (Fail2Ban alternative)
// ============================================================
const loginAttempts = {}; // In-memory store (use Redis in production)

const logStream = fs.createWriteStream(path.join(__dirname, '../logs/access.log'), { flags: 'a' });
app.use(morgan('combined', { stream: logStream }));
app.use(morgan('dev')); // Also log to console

// Intrusion Detection Middleware
function intrusionDetection(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const maxAttempts = 5;

  if (!loginAttempts[ip]) {
    loginAttempts[ip] = { count: 0, firstAttempt: now, blocked: false };
  }

  const attempt = loginAttempts[ip];

  // Reset window if expired
  if (now - attempt.firstAttempt > windowMs) {
    loginAttempts[ip] = { count: 0, firstAttempt: now, blocked: false };
  }

  if (attempt.blocked) {
    console.warn(`[SECURITY ALERT] Blocked IP: ${ip} - Too many login attempts`);
    fs.appendFileSync(path.join(__dirname, '../logs/security.log'),
      `${new Date().toISOString()} - BLOCKED IP: ${ip}\n`);
    return res.status(429).json({
      error: 'Too many failed attempts. IP temporarily blocked.',
      retryAfter: Math.ceil((windowMs - (now - attempt.firstAttempt)) / 1000)
    });
  }

  req.loginAttemptTracker = { ip, attempt };
  next();
}

function recordFailedLogin(ip) {
  if (!loginAttempts[ip]) return;
  loginAttempts[ip].count++;
  if (loginAttempts[ip].count >= 5) {
    loginAttempts[ip].blocked = true;
    console.warn(`[SECURITY ALERT] IP ${ip} has been blocked after 5 failed login attempts!`);
    fs.appendFileSync(path.join(__dirname, '../logs/security.log'),
      `${new Date().toISOString()} - IP BLOCKED: ${ip} - 5 failed attempts\n`);
  }
}

// ============================================================
// WEEK 4 - TASK 2: API SECURITY HARDENING
// ============================================================

// Rate Limiting - General API
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});

// Rate Limiting - Auth endpoints (stricter)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts.' }
});

// CORS Configuration
const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = [
      'http://localhost:3000',
      'https://yourdomain.com',
      'https://app.yourdomain.com'
    ];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`[CORS] Blocked request from origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  credentials: true,
  optionsSuccessStatus: 200
};

// ============================================================
// WEEK 4 - TASK 3: SECURITY HEADERS & CSP
// ============================================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'strict-dynamic'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
      blockAllMixedContent: []
    }
  },
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  xFrameOptions: { action: 'deny' },
  xContentTypeOptions: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  permissionsPolicy: {
    features: {
      geolocation: ["'none'"],
      microphone: ["'none'"],
      camera: ["'none'"]
    }
  }
}));

// ============================================================
// MIDDLEWARE STACK
// ============================================================
app.use(cors(corsOptions));
app.use(express.json({ limit: '10kb' })); // Limit body size
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(generalLimiter);

// Ensure logs directory exists
if (!fs.existsSync(path.join(__dirname, '../logs'))) {
  fs.mkdirSync(path.join(__dirname, '../logs'), { recursive: true });
}

// ============================================================
// API KEY AUTHENTICATION MIDDLEWARE
// ============================================================
const API_KEYS = {
  'intern-key-2024': { user: 'intern', role: 'read' },
  'admin-key-2024': { user: 'admin', role: 'admin' }
};

function apiKeyAuth(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || !API_KEYS[apiKey]) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  req.apiUser = API_KEYS[apiKey];
  next();
}

// JWT Authentication Middleware
function jwtAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// ============================================================
// WEEK 5 - TASK 2: SQL INJECTION PREVENTION (using validation)
// ============================================================

// Input sanitization middleware
function sanitizeInput(req, res, next) {
  // Remove any SQL-injection-like patterns
  const sqlPattern = /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR|AND)\b|--|;|'|")/gi;
  const sanitize = (obj) => {
    if (typeof obj === 'string') {
      if (sqlPattern.test(obj)) {
        console.warn(`[SECURITY] Potential SQLi attempt: ${obj}`);
        fs.appendFileSync(path.join(__dirname, '../logs/security.log'),
          `${new Date().toISOString()} - SQLi ATTEMPT: ${obj}\n`);
        return '';
      }
      return obj.trim();
    }
    if (typeof obj === 'object' && obj !== null) {
      return Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, sanitize(v)]));
    }
    return obj;
  };
  req.body = sanitize(req.body);
  req.query = sanitize(req.query);
  next();
}

app.use(sanitizeInput);

// ============================================================
// WEEK 5 - TASK 3: CSRF PROTECTION
// ============================================================
const csrfProtection = csrf({ cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production' } });

// ============================================================
// MOCK USER DATABASE (In production use PostgreSQL with bcrypt)
// ============================================================
const users = [
  {
    id: 1,
    username: 'admin',
    // Password: "SecurePass123!" - bcrypt hash
    password: '$2a$10$X7iBYMBT1mB.5YqVJZrp8eA5LK8Td.5G3KtrC1f.3iK5U4J9Pk6Oy',
    role: 'admin'
  }
];

// ============================================================
// ROUTES
// ============================================================

// Health Check
app.get('/', (req, res) => {
  res.json({
    message: 'Secure API Server Running',
    week: 'Cybersecurity Internship - Weeks 4-6',
    features: ['Rate Limiting', 'CORS', 'CSP', 'HSTS', 'CSRF', 'JWT Auth', 'SQLi Prevention']
  });
});

// CSRF Token endpoint
app.get('/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// --- AUTH ROUTES ---
app.post('/api/auth/register',
  authLimiter,
  [
    body('username').trim().isLength({ min: 3, max: 30 }).escape(),
    body('password').isLength({ min: 8 })
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage('Password must have uppercase, lowercase, number, and special character'),
    body('email').isEmail().normalizeEmail()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { username, password, email } = req.body;
    const hashedPassword = await bcrypt.hash(password, 12);

    res.status(201).json({
      message: 'User registered successfully',
      user: { username, email, role: 'user' }
    });
  }
);

app.post('/api/auth/login',
  authLimiter,
  intrusionDetection,
  [
    body('username').trim().escape(),
    body('password').notEmpty()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { username, password } = req.body;
    const { ip } = req.loginAttemptTracker;

    const user = users.find(u => u.username === username);
    if (!user) {
      recordFailedLogin(ip);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      recordFailedLogin(ip);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Reset failed attempts on success
    loginAttempts[ip] = { count: 0, firstAttempt: Date.now(), blocked: false };

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      message: 'Login successful',
      token,
      expiresIn: 3600
    });
  }
);

// --- PROTECTED ROUTES ---
app.get('/api/protected', jwtAuth, (req, res) => {
  res.json({
    message: 'You have accessed a protected route!',
    user: req.user,
    timestamp: new Date().toISOString()
  });
});

app.get('/api/admin', jwtAuth, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  res.json({ message: 'Admin panel data', users: users.map(u => ({ id: u.id, username: u.username, role: u.role })) });
});

// API Key protected route
app.get('/api/data', apiKeyAuth, (req, res) => {
  res.json({
    message: 'Data retrieved successfully',
    accessedBy: req.apiUser.user,
    data: [{ id: 1, name: 'Sample Data' }]
  });
});

// CSRF-protected form submission
app.post('/api/form-submit', csrfProtection, jwtAuth, (req, res) => {
  res.json({ message: 'Form submitted securely with CSRF protection' });
});

// ============================================================
// ERROR HANDLING
// ============================================================
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    console.warn(`[SECURITY] CSRF Attack detected from ${req.ip}`);
    fs.appendFileSync(path.join(__dirname, '../logs/security.log'),
      `${new Date().toISOString()} - CSRF ATTACK: ${req.ip}\n`);
    return res.status(403).json({ error: 'Invalid CSRF token - Request blocked' });
  }
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'CORS: Origin not allowed' });
  }
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.listen(PORT, () => {
  console.log(`[SERVER] Running on port ${PORT}`);
  console.log(`[SECURITY] All security middleware active`);
});

module.exports = app;
