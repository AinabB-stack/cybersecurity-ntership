# 🔐 Cybersecurity Internship Project — Weeks 4–6

> **Secure Node.js/Express Application** with advanced threat detection, API hardening, ethical hacking demonstrations, and security audits.

---

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Week 4: Advanced Threat Detection](#week-4-advanced-threat-detection)
- [Week 5: Ethical Hacking](#week-5-ethical-hacking)
- [Week 6: Security Audits](#week-6-security-audits)
- [Setup & Installation](#setup--installation)
- [API Endpoints](#api-endpoints)
- [Security Features](#security-features)
- [Folder Structure](#folder-structure)

---

## 🎯 Project Overview

This project demonstrates the implementation of enterprise-grade security features in a Node.js/Express REST API. It covers:

- Real-time intrusion detection and monitoring
- API security hardening with rate limiting and authentication
- Content Security Policy and HTTPS enforcement
- Ethical hacking and vulnerability remediation
- OWASP Top 10 compliance

---

## 📅 Week 4: Advanced Threat Detection

### Task 1 — Intrusion Detection & Monitoring

- **Morgan** logs all HTTP requests to `logs/access.log`
- Custom security logger writes to `logs/security.log` on suspicious events:
  - Multiple failed login attempts
  - Invalid JWT tokens
  - Invalid API keys
  - Rate limit violations

### Task 2 — API Security Hardening

#### Rate Limiting (`express-rate-limit`)

| Endpoint | Window | Max Requests |
|----------|--------|--------------|
| All `/api/*` | 15 min | 100 |
| `/auth/login` | 15 min | **5** |
| `/api/*` (API) | 1 min | 30 |

#### CORS Configuration

```javascript
origin: ['http://localhost:3000'],   // Whitelist only
methods: ['GET', 'POST', 'PUT', 'DELETE'],
allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key'],
credentials: true
```

#### Authentication Methods

1. **JWT Bearer Token** — All protected routes
2. **API Key** (x-api-key header) — Public API access

### Task 3 — Security Headers (Helmet.js)

| Header | Value |
|--------|-------|
| Content-Security-Policy | `default-src 'self'` |
| Strict-Transport-Security | `max-age=31536000; includeSubDomains; preload` |
| X-Frame-Options | `DENY` |
| X-XSS-Protection | `1; mode=block` |
| X-Content-Type-Options | `nosniff` |
| Referrer-Policy | `same-origin` |

---

## 🕵️ Week 5: Ethical Hacking

### SQL Injection Prevention

**Vulnerable (Before):**
```javascript
db.query(`SELECT * FROM users WHERE email = '${email}'`);
```

**Secure (After — Prepared Statement):**
```javascript
db.query('SELECT * FROM users WHERE email = ?', [email]);
```

SQLMap test result after fix: `all tested parameters appear to be not injectable`

### CSRF Protection

JWT stored in `Authorization` header (not cookie) = CSRF-safe by design.
Browser cannot automatically send custom headers cross-origin.

### Vulnerabilities Found & Fixed

| Vulnerability | Severity | Status |
|--------------|----------|--------|
| SQL Injection | 🔴 HIGH | ✅ Fixed |
| CSRF | 🔴 HIGH | ✅ Fixed |
| No Rate Limiting | 🔴 HIGH | ✅ Fixed |
| Missing Security Headers | 🟡 MEDIUM | ✅ Fixed |
| User Enumeration | 🟡 MEDIUM | ✅ Fixed |

See full report: [`reports/security-audit-report.md`](reports/security-audit-report.md)

---

## 🔍 Week 6: Security Audits

### Tools Used

- **OWASP ZAP** — Dynamic application security testing
- **Nikto** — Web server scanner
- **Lynis** — System security auditing
- **npm audit** — Dependency vulnerability scanning

### OWASP Top 10 Compliance

All 10 OWASP categories addressed. See [`reports/security-audit-report.md`](reports/security-audit-report.md) for details.

### Secure Deployment

- Environment variables via `.env` (never committed)
- Dependencies scanned with `npm audit`
- Graceful shutdown handling

---

## 🚀 Setup & Installation

### Prerequisites

- Node.js >= 16.x
- npm >= 8.x

### Installation

```bash
# Clone repository
git clone https://github.com/your-username/cybersec-internship.git
cd cybersec-internship

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your values

# Start server
npm start

# Development mode
npm run dev
```

### Environment Variables

```env
PORT=3000
JWT_SECRET=your_jwt_secret_min_32_chars
VALID_API_KEYS=your-api-key-1,your-api-key-2
ALLOWED_ORIGINS=http://localhost:3000
```

---

## 📡 API Endpoints

### Auth Routes

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/auth/register` | None | Register new user |
| POST | `/auth/login` | None | Login (rate limited: 5/15min) |

### API Routes

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/status` | API Key | Server status |
| GET | `/api/profile` | JWT | User profile |
| GET | `/api/users/:id` | JWT | Get user by ID |
| POST | `/api/data` | JWT | Submit data |
| GET | `/api/admin/logs` | JWT + Admin | View logs |
| GET | `/health` | None | Health check |

### Example Requests

```bash
# Register
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePass@123"}'

# Login
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePass@123"}'

# Access protected API
curl http://localhost:3000/api/profile \
  -H "Authorization: Bearer <your_jwt_token>"

# Access with API key
curl http://localhost:3000/api/status \
  -H "x-api-key: sk-intern-key-001"
```

---

## 🏗️ Folder Structure

```
cybersecurity-internship-project/
├── src/
│   └── app.js              # Main Express app (security config)
├── routes/
│   ├── auth.js             # Login, Register
│   └── api.js              # Protected API endpoints
├── middleware/
│   └── auth.js             # JWT, API Key, RBAC middleware
├── config/
│   └── (database config)
├── logs/
│   ├── access.log          # All HTTP requests
│   ├── security.log        # Security events
│   └── errors.log          # Application errors
├── reports/
│   └── security-audit-report.md
├── .env.example
├── .gitignore
├── package.json
├── server.js               # Entry point
└── README.md
```

---

## 🔒 Security Features Summary

| Feature | Implementation | Week |
|---------|---------------|------|
| Rate Limiting | express-rate-limit | 4 |
| CORS | cors package | 4 |
| Security Headers | helmet | 4 |
| CSP | helmet CSP | 4 |
| HSTS | helmet HSTS | 4 |
| JWT Auth | jsonwebtoken | 4 |
| API Key Auth | Custom middleware | 4 |
| Password Hashing | bcryptjs (12 rounds) | 4 |
| SQL Injection Prevention | Prepared statements | 5 |
| CSRF Protection | JWT in header | 5 |
| Input Validation | express-validator | 5 |
| Security Logging | Morgan + Custom | 4-6 |
| OWASP Top 10 | All 10 addressed | 6 |

---

## 👨‍💻 Author

**Cybersecurity Intern** | April 2026

---

> ⚠️ **Disclaimer:** This project is for educational purposes. All penetration testing was performed on local test environments only.
