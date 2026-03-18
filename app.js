const express = require('express');
const validator = require('validator');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const winston = require('winston');

const app = express();
app.use(helmet()); // Helmet Security Headers (Week 2)

// --- WEEK 3: Winston Logging Setup ---
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    ),
    transports: [
        new winston.transports.File({ filename: 'security.log' }), // Logs to file
        new winston.transports.Console() // Shows in Terminal
    ]
});

async function runSecurityAudit() {
    console.log("\n=====================================");
    console.log("   WEEK 2 & 3: SECURITY AUDIT       ");
    console.log("=====================================\n");

    // 1. XSS Protection (Week 2)
    const dirtyInput = "<script>alert('XSS Attack!')</script>";
    const cleanInput = validator.escape(dirtyInput);
    logger.info(`XSS_PROTECTION: Input Sanitized. Result: ${cleanInput}`);

    // 2. Password Hashing (Week 2)
    const myPassword = "AinabPassword123";
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(myPassword, saltRounds);
    logger.info(`PASSWORD_SECURITY: Bcrypt Hash Generated: ${hashedPassword}`);

    // 3. JWT Authentication (Week 2)
    const userPayload = { username: "Ainab", role: "Intern" };
    const token = jwt.sign(userPayload, 'super_secret_key', { expiresIn: '1h' });
    logger.info(`JWT_AUTH: Secure Token Generated: ${token}`);

    console.log("\nAudit Complete. Check 'security.log' file in your folder.");
}

// Run the audit
runSecurityAudit();

// Start Server
const PORT = 3000;
app.listen(PORT, () => {
    logger.info(`SERVER_STATUS: Running on http://localhost:${PORT}`);
});