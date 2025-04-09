const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const slowDown = require('express-slow-down');
const morgan = require('morgan');
const app = express();
const port = 3002;

app.use(cors());
app.use(morgan('combined'));

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
    }
  },
  hsts: { maxAge: 31536000 }
}));

let requestCount = 0;
let requestsPerSecond = [];
const DDOS_THRESHOLD = 20000;
let violationCount = 0;
let underDDoSAttack = false;

app.use((req, res, next) => {
  requestCount++;
  next();
});

setInterval(() => {
  requestsPerSecond.push(requestCount);
  if (requestsPerSecond.length > 30) requestsPerSecond.shift();
  requestCount = 0;
}, 1000);

const blacklist = new Set();
const whitelist = new Set(['127.0.0.1']);
const MAX_VIOLATIONS = 4;
const ipViolations = new Map();
const ipConnections = new Map();
const requestTimestamps = new Map();
const MAX_CONNECTIONS_PER_IP = 6;
const MAX_REQUESTS_PER_SECOND = 4;

const globalLimiter = rateLimit({
  windowMs: 10 * 1000,
  max: 20,
  store: new rateLimit.MemoryStore(),
  keyGenerator: (req) => req.ip + (req.headers['user-agent'] || 'unknown'),
  handler: (req, res) => {
    blacklist.add(req.ip);
    violationCount++;
    res.status(429).end();
  }
});

const apiLimiter = rateLimit({
  windowMs: 12 * 1000,
  max: 10,
  handler: (req, res) => {
    violationCount++;
    res.status(429).end();
  }
});

const speedLimiter = slowDown({
  windowMs: 12 * 1000,
  delayAfter: 6,
  delayMs: (used) => Math.min(10000, (used - 6) * 1000),
  maxDelayMs: 10000
});

const checkDDoS = (req, res, next) => {
  if (underDDoSAttack) {
    return res.redirect(302, 'https://google.com');
  }
  next();
};

const checkSecurity = (req, res, next) => {
  const ip = req.ip;

  if (whitelist.has(ip)) return next();
  if (blacklist.has(ip)) {
    violationCount++;
    return res.status(403).end();
  }

  const connections = ipConnections.get(ip) || 0;
  if (connections >= MAX_CONNECTIONS_PER_IP) {
    blacklist.add(ip);
    violationCount++;
    return res.status(403).end();
  }
  ipConnections.set(ip, connections + 1);
  setTimeout(() => ipConnections.set(ip, Math.max(0, ipConnections.get(ip) - 1)), 20000);

  const timestamps = requestTimestamps.get(ip) || [];
  const now = Date.now();
  const recentRequests = timestamps.filter(ts => now - ts < 1000);
  if (recentRequests.length >= MAX_REQUESTS_PER_SECOND) {
    blacklist.add(ip);
    violationCount++;
    return res.status(429).end();
  }
  requestTimestamps.set(ip, [...recentRequests, now].slice(-20));

  next();
};

const botnetDetector = (req, res, next) => {
  const ip = req.ip;
  const now = Date.now();
  const violations = ipViolations.get(ip) || { count: 0, lastTime: now };

  if (now - violations.lastTime < 40) {
    violations.count++;
  } else {
    violations.count = Math.max(0, violations.count - 1);
  }

  violations.lastTime = now;
  ipViolations.set(ip, violations);

  if (violations.count >= MAX_VIOLATIONS) {
    blacklist.add(ip);
    violationCount++;
    return res.status(403).end();
  }

  const forwarded = req.headers['x-forwarded-for'];
  const userAgent = req.headers['user-agent'] || '';
  if (forwarded && forwarded.split(',').length > 2) {
    blacklist.add(ip);
    violationCount++;
    return res.status(403).end();
  }
  if (!userAgent || /bot|crawl|spider/i.test(userAgent)) {
    violationCount++;
    return res.status(403).end();
  }

  next();
};

app.use(checkDDoS);
app.use(checkSecurity);
app.use(botnetDetector);
app.use(globalLimiter);
app.use(speedLimiter);

app.get('/', (req, res) => {
  res.status(200).send('<a href="https://t.me/tretraunetwork">https://t.me/tretraunetwork</a>');
});

app.get('/api/requests', apiLimiter, (req, res) => {
  res.status(200).json(requestsPerSecond);
});

app.use((err, req, res, next) => {
  res.status(500).end();
});

setInterval(() => {
  if (violationCount >= DDOS_THRESHOLD) {
    console.log('DDoS attack detected! Redirecting to google.com');
    underDDoSAttack = true;
  } else {
    underDDoSAttack = false;
  }
  violationCount = 0;
  blacklist.clear();
  ipViolations.clear();
  ipConnections.clear();
  requestTimestamps.clear();
}, 10 * 1000);

app.listen(port, () => {
  console.log(`Server 3 (Anti-DDoS Strong) running on http://localhost:${port}`);
});