const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const JWT_EXPIRES_IN = '24h';

// ==================== SECURITY MIDDLEWARE ====================

const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;
const MAX_REQUESTS_PER_WINDOW = 100;

const rateLimit = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  
  if (!rateLimitStore.has(ip)) {
    rateLimitStore.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
  } else {
    const record = rateLimitStore.get(ip);
    if (now > record.resetTime) {
      rateLimitStore.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    } else {
      record.count++;
    }
  }
  
  const record = rateLimitStore.get(ip);
  res.setHeader('X-RateLimit-Limit', MAX_REQUESTS_PER_WINDOW);
  res.setHeader('X-RateLimit-Remaining', Math.max(0, MAX_REQUESTS_PER_WINDOW - record.count));
  
  if (record.count > MAX_REQUESTS_PER_WINDOW) {
    return res.status(429).json({ 
      error: 'Too many requests. Please try again later.',
      retryAfter: Math.ceil((record.resetTime - Date.now()) / 1000)
    });
  }
  next();
};

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});

const sanitizeInput = (req, res, next) => {
  const sanitize = (obj) => {
    if (typeof obj === 'string') {
      return obj.trim().replace(/[<>\"'&]/g, '');
    }
    if (typeof obj === 'object' && obj !== null) {
      for (const key in obj) {
        obj[key] = sanitize(obj[key]);
      }
    }
    return obj;
  };
  
  if (req.body) req.body = sanitize(req.body);
  if (req.query) req.query = sanitize(req.query);
  next();
};

const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const isStrongPassword = (password) => {
  return password.length >= 8;
};

// ==================== CRYPTOCURRENCIES ====================

const CRYPTOS = [
  { id: 'bitcoin', symbol: 'BTC', name: 'Bitcoin', network: 'Bitcoin', decimals: 8, fee: 0.0001, stakingApy: 0 },
  { id: 'ethereum', symbol: 'ETH', name: 'Ethereum', network: 'Ethereum', decimals: 18, fee: 0.002, stakingApy: 4.5 },
  { id: 'tether', symbol: 'USDT', name: 'Tether', network: 'Ethereum', decimals: 6, fee: 5, stakingApy: 0 },
  { id: 'binancecoin', symbol: 'BNB', name: 'BNB', network: 'Binance', decimals: 8, fee: 0.002, stakingApy: 8.2 },
  { id: 'solana', symbol: 'SOL', name: 'Solana', network: 'Solana', decimals: 9, fee: 0.00001, stakingApy: 7.1 },
  { id: 'ripple', symbol: 'XRP', name: 'XRP', network: 'XRP Ledger', decimals: 6, fee: 0.01, stakingApy: 0 },
  { id: 'cardano', symbol: 'ADA', name: 'Cardano', network: 'Cardano', decimals: 6, fee: 0.2, stakingApy: 5.0 },
  { id: 'dogecoin', symbol: 'DOGE', name: 'Dogecoin', network: 'Dogecoin', decimals: 8, fee: 1, stakingApy: 0 },
  { id: 'polygon', symbol: 'MATIC', name: 'Polygon', network: 'Polygon', decimals: 18, fee: 0.01, stakingApy: 5.5 },
  { id: 'tron', symbol: 'TRX', name: 'Tron', network: 'Tron', decimals: 6, fee: 1, stakingApy: 3.8 },
  { id: 'polkadot', symbol: 'DOT', name: 'Polkadot', network: 'Polkadot', decimals: 10, fee: 0.1, stakingApy: 12.0 },
  { id: 'avalanche', symbol: 'AVAX', name: 'Avalanche', network: 'Avalanche', decimals: 18, fee: 0.025, stakingApy: 9.5 }
];

const SIMULATED_PRICES = {
  bitcoin: 43250.00, ethereum: 2280.50, tether: 1.00, binancecoin: 312.40,
  solana: 98.75, ripple: 0.62, cardano: 0.58, dogecoin: 0.082, polygon: 0.85, tron: 0.10,
  polkadot: 8.45, avalanche: 35.20
};

// ==================== DATABASE (In-Memory) ====================

let users = [
  { id: 1, name: 'Admin User', email: 'admin@cryptowallet.com', role: 'admin', verified: true, twoFactorEnabled: false, createdAt: new Date().toISOString() },
  { id: 2, name: 'John Doe', email: 'john@example.com', role: 'user', verified: true, twoFactorEnabled: false, createdAt: new Date().toISOString() },
  { id: 3, name: 'Jane Smith', email: 'jane@example.com', role: 'user', verified: true, twoFactorEnabled: false, createdAt: new Date().toISOString() }
];

// Hash default passwords
users[0].password = bcrypt.hashSync('admin123', 10);
users[1].password = bcrypt.hashSync('password123', 10);
users[2].password = bcrypt.hashSync('password123', 10);

let sessions = new Map();
let loginAttempts = new Map();
let wallets = {};
let transactions = {};
let priceAlerts = {};
let addressBook = {};
let multiSigWallets = {};
let auditLogs = [];
let stakingPositions = {};
let swapHistory = {};
let batchTransactions = {};
let portfolioHistory = {};

// Initialize default user wallet data
wallets[users[0].id] = [];
transactions[users[0].id] = [];
priceAlerts[users[0].id] = [];
addressBook[users[0].id] = [];
multiSigWallets[users[0].id] = [];
stakingPositions[users[0].id] = [];
swapHistory[users[0].id] = [];
batchTransactions[users[0].id] = [];
portfolioHistory[users[0].id] = [];

wallets[users[1].id] = [];
transactions[users[1].id] = [];
priceAlerts[users[1].id] = [];
addressBook[users[1].id] = [];
multiSigWallets[users[1].id] = [];
stakingPositions[users[1].id] = [];
swapHistory[users[1].id] = [];
batchTransactions[users[1].id] = [];
portfolioHistory[users[1].id] = [];

wallets[users[2].id] = [];
transactions[users[2].id] = [];
priceAlerts[users[2].id] = [];
addressBook[users[2].id] = [];
multiSigWallets[users[2].id] = [];
stakingPositions[users[2].id] = [];
swapHistory[users[2].id] = [];
batchTransactions[users[2].id] = [];
portfolioHistory[users[2].id] = [];

// ==================== HELPER FUNCTIONS ====================

const generateAddress = (cryptoId) => {
  const prefixes = { bitcoin: '1', ethereum: '0x', solana: 'Sol', ripple: 'r', cardano: 'addr1' };
  const prefix = prefixes[cryptoId] || '';
  return prefix + generateRandomString(cryptoId === 'solana' ? 44 : 34);
};

const generateRandomString = (length) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
};

const generateTxHash = () => {
  return '0x' + generateRandomString(64);
};

const calculateGasFees = (cryptoId, networkCongestion = 'normal') => {
  const baseFees = {
    bitcoin: { slow: 0.00001, average: 0.00002, fast: 0.00005 },
    ethereum: { slow: 15, average: 25, fast: 45 },
    solana: { slow: 0.000005, average: 0.00001, fast: 0.00002 },
    polygon: { slow: 0.001, average: 0.01, fast: 0.05 }
  };
  
  const fees = baseFees[cryptoId] || { slow: 0.001, average: 0.002, fast: 0.005 };
  const multiplier = networkCongestion === 'high' ? 2 : networkCongestion === 'low' ? 0.5 : 1;
  
  return {
    slow: (fees.slow * multiplier).toFixed(8),
    average: (fees.average * multiplier).toFixed(8),
    fast: (fees.fast * multiplier).toFixed(8),
    estimatedTime: networkCongestion === 'high' ? '30-60 min' : networkCongestion === 'low' ? '5-10 min' : '10-20 min'
  };
};

// ==================== MIDDLEWARE ====================

app.use(rateLimit);
app.use(cors());
app.use(express.json({ limit: '10kb' }));
app.use(sanitizeInput);

app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const session = sessions.get(token);
    if (!session || session.userId !== decoded.userId) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    
    if (session.lastActivity && Date.now() - session.lastActivity > 30 * 60 * 1000) {
      sessions.delete(token);
      return res.status(401).json({ error: 'Session expired. Please login again.' });
    }
    
    session.lastActivity = Date.now();
    sessions.set(token, session);
    
    req.userId = decoded.userId;
    req.userRole = decoded.role;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

const requireAdmin = (req, res, next) => {
  if (req.userRole !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

const requireVerified = (req, res, next) => {
  const user = users.find(u => u.id === req.userId);
  if (!user || !user.verified) {
    return res.status(403).json({ error: 'Email verification required' });
  }
  next();
};

const logAudit = (userId, action, details) => {
  auditLogs.push({
    id: uuidv4(),
    userId,
    action,
    details,
    ip: '127.0.0.1',
    timestamp: new Date().toISOString()
  });
};

// ==================== AUTH ROUTES ====================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (name.length < 2 || name.length > 100) {
      return res.status(400).json({ error: 'Name must be 2-100 characters' });
    }
    
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    
    if (!isStrongPassword(password)) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    const existingUser = users.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = uuidv4();
    
    const newUser = {
      id: Date.now(),
      name,
      email,
      password: hashedPassword,
      role: 'user',
      verified: false,
      verificationToken,
      twoFactorEnabled: false,
      twoFactorSecret: null,
      createdAt: new Date().toISOString()
    };
    
    users.push(newUser);
    wallets[newUser.id] = [];
    transactions[newUser.id] = [];
    priceAlerts[newUser.id] = [];
    addressBook[newUser.id] = [];
    multiSigWallets[newUser.id] = [];
    stakingPositions[newUser.id] = [];
    swapHistory[newUser.id] = [];
    batchTransactions[newUser.id] = [];
    portfolioHistory[newUser.id] = [];
    
    logAudit(newUser.id, 'USER_REGISTERED', { email });
    
    res.status(201).json({
      message: 'Registration successful. Please verify your email.',
      user: { id: newUser.id, name, email, role: 'user' }
    });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, twoFactorCode } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    
    const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (!user) {
      await bcrypt.compare(password, '$2a$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const userAttempts = loginAttempts.get(user.id) || { count: 0, resetTime: Date.now() + 15 * 60 * 1000 };
    if (userAttempts.count >= 5 && Date.now() < userAttempts.resetTime) {
      return res.status(429).json({ error: 'Too many login attempts. Try again in 15 minutes.' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      loginAttempts.set(user.id, { count: userAttempts.count + 1, resetTime: userAttempts.resetTime });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    if (user.twoFactorEnabled) {
      if (!twoFactorCode) {
        return res.status(200).json({ requireTwoFactor: true });
      }
      
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: twoFactorCode
      });
      
      if (!verified) {
        return res.status(401).json({ error: 'Invalid 2FA code' });
      }
    }
    
    if (!user.verified) {
      return res.status(403).json({ error: 'Please verify your email first' });
    }
    
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );
    
    sessions.set(token, {
      userId: user.id,
      email: user.email,
      role: user.role,
      createdAt: Date.now(),
      lastActivity: Date.now()
    });
    
    if (!wallets[user.id]) wallets[user.id] = [];
    if (!transactions[user.id]) transactions[user.id] = [];
    if (!priceAlerts[user.id]) priceAlerts[user.id] = [];
    if (!addressBook[user.id]) addressBook[user.id] = [];
    
    loginAttempts.delete(user.id);
    logAudit(user.id, 'USER_LOGIN', { email });
    
    const { password: _, verificationToken: __, twoFactorSecret: ___, ...userWithoutSensitive } = user;
    
    res.json({
      message: 'Login successful',
      token,
      user: userWithoutSensitive,
      expiresIn: JWT_EXPIRES_IN
    });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/logout', authenticate, (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token) {
    sessions.delete(token);
    logAudit(req.userId, 'USER_LOGOUT', {});
  }
  res.json({ message: 'Logged out successfully' });
});

app.post('/api/auth/refresh', authenticate, (req, res) => {
  const token = jwt.sign(
    { userId: req.userId, email: req.userRole, role: req.userRole },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
  
  const oldToken = req.headers.authorization?.replace('Bearer ', '');
  sessions.delete(oldToken);
  
  sessions.set(token, {
    userId: req.userId,
    role: req.userRole,
    createdAt: Date.now(),
    lastActivity: Date.now()
  });
  
  res.json({ token, expiresIn: JWT_EXPIRES_IN });
});

app.get('/api/auth/me', authenticate, (req, res) => {
  const user = users.find(u => u.id === req.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  const { password: _, verificationToken: __, twoFactorSecret: ___, ...userWithoutSensitive } = user;
  res.json({ user: userWithoutSensitive });
});

app.get('/api/auth/verify/:token', (req, res) => {
  const { token } = req.params;
  const user = users.find(u => u.verificationToken === token);
  
  if (!user) {
    return res.status(400).json({ error: 'Invalid verification token' });
  }
  
  user.verified = true;
  user.verificationToken = null;
  logAudit(user.id, 'EMAIL_VERIFIED', {});
  
  res.json({ message: 'Email verified successfully' });
});

app.post('/api/auth/resend-verification', authenticate, (req, res) => {
  const user = users.find(u => u.id === req.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  if (user.verified) {
    return res.status(400).json({ error: 'Email already verified' });
  }
  
  user.verificationToken = uuidv4();
  res.json({ message: 'Verification email resent' });
});

app.post('/api/auth/2fa/setup', authenticate, async (req, res) => {
  const user = users.find(u => u.id === req.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  const secret = speakeasy.generateSecret({
    name: `CryptoWallet:${user.email}`
  });
  
  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
  
  user.twoFactorSecret = secret.base32;
  
  res.json({
    secret: secret.base32,
    qrCode: qrCodeUrl,
    message: 'Scan this QR code with Google Authenticator'
  });
});

app.post('/api/auth/2fa/verify', authenticate, (req, res) => {
  const { code } = req.body;
  const user = users.find(u => u.id === req.userId);
  
  if (!user || !user.twoFactorSecret) {
    return res.status(400).json({ error: '2FA not setup' });
  }
  
  const verified = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: 'base32',
    token: code
  });
  
  if (verified) {
    user.twoFactorEnabled = true;
    logAudit(user.id, '2FA_ENABLED', {});
    res.json({ message: '2FA enabled successfully' });
  } else {
    res.status(400).json({ error: 'Invalid code' });
  }
});

app.post('/api/auth/2fa/disable', authenticate, async (req, res) => {
  const { code, password } = req.body;
  const user = users.find(u => u.id === req.userId);
  
  if (!user || !user.twoFactorEnabled) {
    return res.status(400).json({ error: '2FA not enabled' });
  }
  
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(401).json({ error: 'Invalid password' });
  }
  
  const verified = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: 'base32',
    token: code
  });
  
  if (verified) {
    user.twoFactorEnabled = false;
    user.twoFactorSecret = null;
    logAudit(user.id, '2FA_DISABLED', {});
    res.json({ message: '2FA disabled successfully' });
  } else {
    res.status(400).json({ error: 'Invalid 2FA code' });
  }
});

// ==================== CRYPTO ROUTES ====================

app.get('/api/crypto', (req, res) => {
  res.json(CRYPTOS);
});

app.get('/api/crypto/staking', authenticate, (req, res) => {
  const stakingInfo = CRYPTOS.filter(c => c.stakingApy > 0).map(crypto => ({
    ...crypto,
    price: SIMULATED_PRICES[crypto.id],
    stakingApy: crypto.stakingApy,
    minStake: crypto.id === 'ethereum' ? 0.01 : crypto.id === 'solana' ? 0.5 : 10,
    lockPeriod: crypto.id === 'ethereum' ? 'Unlocked' : crypto.id === 'solana' ? '9-30 days' : '7-90 days',
    rewardsFrequency: 'Daily'
  }));
  res.json(stakingInfo);
});

app.get('/api/crypto/prices', authenticate, (req, res) => {
  const prices = CRYPTOS.map(crypto => ({
    ...crypto,
    price: SIMULATED_PRICES[crypto.id],
    priceChange24h: (Math.random() * 10 - 5).toFixed(2),
    stakingApy: crypto.stakingApy,
    lastUpdated: new Date().toISOString()
  }));
  res.json(prices);
});

app.get('/api/crypto/price/:id', authenticate, (req, res) => {
  const crypto = CRYPTOS.find(c => c.id === req.params.id);
  if (!crypto) {
    return res.status(404).json({ error: 'Cryptocurrency not found' });
  }
  res.json({
    ...crypto,
    price: SIMULATED_PRICES[crypto.id],
    priceChange24h: (Math.random() * 10 - 5).toFixed(2),
    lastUpdated: new Date().toISOString()
  });
});

app.get('/api/crypto/gas-fees/:cryptoId', authenticate, (req, res) => {
  const { cryptoId } = req.params;
  const { congestion = 'normal' } = req.query;
  
  const crypto = CRYPTOS.find(c => c.id === cryptoId);
  if (!crypto) {
    return res.status(404).json({ error: 'Cryptocurrency not found' });
  }
  
  const fees = calculateGasFees(cryptoId, congestion);
  res.json({
    cryptoId,
    cryptoSymbol: crypto.symbol,
    network: crypto.network,
    ...fees,
    currentCongestion: congestion,
    suggested: congestion === 'normal' ? 'average' : congestion
  });
});

// ==================== WALLET ROUTES ====================

app.get('/api/wallets', authenticate, requireVerified, (req, res) => {
  const userWallets = wallets[req.userId] || [];
  const portfolio = userWallets.map(wallet => {
    const crypto = CRYPTOS.find(c => c.id === wallet.cryptoId);
    const currentPrice = SIMULATED_PRICES[wallet.cryptoId] || 0;
    return {
      ...wallet,
      cryptoName: crypto?.name || wallet.cryptoId,
      cryptoSymbol: crypto?.symbol || wallet.cryptoId,
      currentPrice,
      valueUsd: (wallet.balance * currentPrice).toFixed(2),
      encryptedPrivateKey: wallet.encryptedPrivateKey ? '[PROTECTED]' : null
    };
  });
  res.json(portfolio);
});

app.post('/api/wallets', authenticate, requireVerified, async (req, res) => {
  const { cryptoId } = req.body;
  
  const crypto = CRYPTOS.find(c => c.id === cryptoId);
  if (!crypto) {
    return res.status(400).json({ error: 'Invalid cryptocurrency' });
  }
  
  const existingWallets = wallets[req.userId] || [];
  if (existingWallets.find(w => w.cryptoId === cryptoId)) {
    return res.status(400).json({ error: 'Wallet already exists for this crypto' });
  }
  
  const address = generateAddress(cryptoId);
  const privateKey = generateRandomString(64);
  const encryptedPrivateKey = await bcrypt.hash(privateKey, 10);
  
  const newWallet = {
    id: uuidv4(),
    cryptoId,
    symbol: crypto.symbol,
    name: crypto.name,
    address,
    encryptedPrivateKey,
    balance: 0,
    createdAt: new Date().toISOString()
  };
  
  if (!wallets[req.userId]) wallets[req.userId] = [];
  wallets[req.userId].push(newWallet);
  
  logAudit(req.userId, 'WALLET_CREATED', { cryptoId, walletId: newWallet.id });
  
  res.status(201).json({
    ...newWallet,
    decryptedPrivateKey: privateKey
  });
});

app.get('/api/wallets/:id', authenticate, requireVerified, (req, res) => {
  const wallet = (wallets[req.userId] || []).find(w => w.id === req.params.id);
  if (!wallet) {
    return res.status(404).json({ error: 'Wallet not found' });
  }
  res.json(wallet);
});

// ==================== PORTFOLIO ROUTES ====================

app.get('/api/portfolio', authenticate, requireVerified, (req, res) => {
  const userWallets = wallets[req.userId] || [];
  
  let totalValueUsd = 0;
  const holdings = userWallets.map(wallet => {
    const price = SIMULATED_PRICES[wallet.cryptoId] || 0;
    const value = wallet.balance * price;
    totalValueUsd += value;
    return {
      cryptoId: wallet.cryptoId,
      symbol: wallet.symbol,
      name: wallet.name,
      balance: wallet.balance,
      priceUsd: price,
      valueUsd: value.toFixed(2)
    };
  });
  
  const change24h = (Math.random() * 10 - 3).toFixed(2);
  
  res.json({
    totalValueUsd: totalValueUsd.toFixed(2),
    change24h,
    changeValue: (totalValueUsd * change24h / 100).toFixed(2),
    holdings,
    lastUpdated: new Date().toISOString()
  });
});

app.get('/api/portfolio/analytics', authenticate, requireVerified, (req, res) => {
  const userWallets = wallets[req.userId] || [];
  const history = portfolioHistory[req.userId] || [];
  
  // Generate 30-day history if not exists
  if (history.length === 0) {
    let baseValue = 10000;
    for (let i = 30; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      baseValue = baseValue * (1 + (Math.random() * 0.04 - 0.015));
      history.push({
        date: date.toISOString().split('T')[0],
        value: baseValue.toFixed(2),
        change: (Math.random() * 10 - 5).toFixed(2)
      });
    }
    portfolioHistory[req.userId] = history;
  }
  
  const allocations = userWallets.map(wallet => {
    const price = SIMULATED_PRICES[wallet.cryptoId] || 0;
    const value = wallet.balance * price;
    return {
      cryptoId: wallet.cryptoId,
      symbol: wallet.symbol,
      name: wallet.name,
      value: value.toFixed(2),
      percentage: 0 // Will be calculated
    };
  });
  
  const totalValue = parseFloat(allocations.reduce((sum, a) => sum + parseFloat(a.value), 0).toFixed(2));
  allocations.forEach(a => {
    a.percentage = totalValue > 0 ? ((parseFloat(a.value) / totalValue) * 100).toFixed(1) : 0;
  });
  
  const performance = {
    day: (Math.random() * 10 - 3).toFixed(2),
    week: (Math.random() * 15 - 5).toFixed(2),
    month: (Math.random() * 25 - 8).toFixed(2),
    year: (Math.random() * 80 - 20).toFixed(2),
    allTime: (Math.random() * 150 - 30).toFixed(2)
  };
  
  res.json({
    totalValue: totalValue.toFixed(2),
    history,
    allocations,
    performance,
    riskScore: Math.floor(Math.random() * 30 + 30),
    sharpeRatio: (Math.random() * 2 + 0.5).toFixed(2),
    volatility: (Math.random() * 30 + 15).toFixed(2),
    lastUpdated: new Date().toISOString()
  });
});

// ==================== TRANSACTION ROUTES ====================

app.get('/api/transactions', authenticate, requireVerified, (req, res) => {
  const { status, type, cryptoId, page = 1, limit = 50 } = req.query;
  let userTransactions = transactions[req.userId] || [];
  
  if (status) userTransactions = userTransactions.filter(t => t.status === status);
  if (type) userTransactions = userTransactions.filter(t => t.type === type);
  if (cryptoId) userTransactions = userTransactions.filter(t => t.cryptoId === cryptoId);
  
  const start = (page - 1) * limit;
  const paginated = userTransactions.slice(start, start + parseInt(limit));
  
  res.json({
    transactions: paginated.reverse(),
    total: userTransactions.length,
    page: parseInt(page),
    totalPages: Math.ceil(userTransactions.length / limit)
  });
});

app.post('/api/transactions/send', authenticate, requireVerified, async (req, res) => {
  try {
    const { cryptoId, amount, toAddress, memo, feeLevel = 'average', gasLimit } = req.body;
    
    if (!cryptoId || !amount || !toAddress) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const sendAmount = parseFloat(amount);
    if (isNaN(sendAmount) || sendAmount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    
    const crypto = CRYPTOS.find(c => c.id === cryptoId);
    if (!crypto) {
      return res.status(400).json({ error: 'Invalid cryptocurrency' });
    }
    
    const userWallets = wallets[req.userId] || [];
    const wallet = userWallets.find(w => w.cryptoId === cryptoId);
    
    if (!wallet) {
      return res.status(404).json({ error: 'Wallet not found' });
    }
    
    const feeLevels = { slow: 0.5, average: 1, fast: 2 };
    const feeMultiplier = feeLevels[feeLevel] || 1;
    const fee = (crypto.fee * feeMultiplier).toFixed(crypto.decimals);
    
    const totalRequired = sendAmount + parseFloat(fee);
    
    if (wallet.balance < totalRequired) {
      return res.status(400).json({ 
        error: 'Insufficient balance',
        required: totalRequired,
        available: wallet.balance,
        fee
      });
    }
    
    wallet.balance -= totalRequired;
    
    const tx = {
      id: uuidv4(),
      type: 'send',
      cryptoId,
      symbol: crypto.symbol,
      amount: sendAmount,
      toAddress,
      memo: memo || '',
      status: 'pending',
      fee,
      networkFee: fee,
      timestamp: new Date().toISOString(),
      hash: null,
      confirmations: 0
    };
    
    if (!transactions[req.userId]) transactions[req.userId] = [];
    transactions[req.userId].push(tx);
    
    logAudit(req.userId, 'TRANSACTION_SENT', { cryptoId, amount: sendAmount, txId: tx.id });
    
    setTimeout(() => {
      const storedTx = (transactions[req.userId] || []).find(t => t.id === tx.id);
      if (storedTx) {
        storedTx.status = 'confirmed';
        storedTx.hash = generateTxHash();
        storedTx.confirmations = 6;
        storedTx.confirmedAt = new Date().toISOString();
      }
    }, 30000);
    
    res.status(201).json({ 
      message: 'Transaction initiated',
      transaction: tx,
      fee
    });
  } catch (err) {
    res.status(500).json({ error: 'Transaction failed' });
  }
});

app.post('/api/transactions/receive', authenticate, requireVerified, (req, res) => {
  const { cryptoId, amount, fromAddress, txHash } = req.body;
  
  if (!cryptoId || !amount || !fromAddress) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  const crypto = CRYPTOS.find(c => c.id === cryptoId);
  if (!crypto) {
    return res.status(400).json({ error: 'Invalid cryptocurrency' });
  }
  
  let userWallets = wallets[req.userId] || [];
  let wallet = userWallets.find(w => w.cryptoId === cryptoId);
  
  if (!wallet) {
    wallet = {
      id: uuidv4(),
      cryptoId,
      symbol: crypto.symbol,
      name: crypto.name,
      address: generateAddress(cryptoId),
      balance: 0,
      createdAt: new Date().toISOString()
    };
    wallets[req.userId].push(wallet);
    userWallets = wallets[req.userId];
  }
  
  wallet.balance += parseFloat(amount);
  
  const tx = {
    id: uuidv4(),
    type: 'receive',
    cryptoId,
    symbol: crypto.symbol,
    amount: parseFloat(amount),
    fromAddress,
    status: 'confirmed',
    txHash: txHash || generateTxHash(),
    timestamp: new Date().toISOString(),
    confirmations: 6,
    confirmedAt: new Date().toISOString()
  };
  
  if (!transactions[req.userId]) transactions[req.userId] = [];
  transactions[req.userId].push(tx);
  
  logAudit(req.userId, 'TRANSACTION_RECEIVED', { cryptoId, amount, txId: tx.id });
  
  res.json({ message: 'Crypto received', transaction: tx });
});

app.get('/api/transactions/:id', authenticate, requireVerified, (req, res) => {
  const tx = (transactions[req.userId] || []).find(t => t.id === req.params.id);
  if (!tx) {
    return res.status(404).json({ error: 'Transaction not found' });
  }
  res.json(tx);
});

// ==================== BATCH TRANSACTION ROUTES ====================

app.post('/api/batch/create', authenticate, requireVerified, (req, res) => {
  const { name, transactions: txList } = req.body;
  
  if (!txList || !Array.isArray(txList) || txList.length === 0) {
    return res.status(400).json({ error: 'Transactions list required' });
  }
  
  if (txList.length > 10) {
    return res.status(400).json({ error: 'Maximum 10 transactions per batch' });
  }
  
  const batch = {
    id: uuidv4(),
    name: name || `Batch ${new Date().toISOString()}`,
    transactions: txList.map(tx => ({
      ...tx,
      id: uuidv4(),
      status: 'pending',
      timestamp: new Date().toISOString()
    })),
    status: 'pending',
    createdAt: new Date().toISOString()
  };
  
  if (!batchTransactions[req.userId]) batchTransactions[req.userId] = [];
  batchTransactions[req.userId].push(batch);
  
  logAudit(req.userId, 'BATCH_CREATED', { batchId: batch.id, txCount: txList.length });
  
  res.status(201).json({ message: 'Batch created', batch });
});

app.get('/api/batch', authenticate, requireVerified, (req, res) => {
  const batches = batchTransactions[req.userId] || [];
  res.json(batches);
});

app.post('/api/batch/:id/execute', authenticate, requireVerified, async (req, res) => {
  const batch = (batchTransactions[req.userId] || []).find(b => b.id === req.params.id);
  
  if (!batch) {
    return res.status(404).json({ error: 'Batch not found' });
  }
  
  if (batch.status === 'executed') {
    return res.status(400).json({ error: 'Batch already executed' });
  }
  
  const results = [];
  
  for (const tx of batch.transactions) {
    try {
      const crypto = CRYPTOS.find(c => c.id === tx.cryptoId);
      const wallet = (wallets[req.userId] || []).find(w => w.cryptoId === tx.cryptoId);
      
      if (!wallet || wallet.balance < (tx.amount + tx.fee || 0)) {
        results.push({ txId: tx.id, status: 'failed', error: 'Insufficient balance' });
        continue;
      }
      
      wallet.balance -= (tx.amount + (tx.fee || 0));
      
      const transaction = {
        id: tx.id,
        type: 'send',
        cryptoId: tx.cryptoId,
        symbol: crypto.symbol,
        amount: tx.amount,
        toAddress: tx.toAddress,
        status: 'pending',
        fee: tx.fee || crypto.fee,
        timestamp: new Date().toISOString(),
        batchId: batch.id
      };
      
      if (!transactions[req.userId]) transactions[req.userId] = [];
      transactions[req.userId].push(transaction);
      
      results.push({ txId: tx.id, status: 'success', txId: transaction.id });
      
    } catch (err) {
      results.push({ txId: tx.id, status: 'failed', error: err.message });
    }
  }
  
  batch.status = 'executed';
  batch.executedAt = new Date().toISOString();
  batch.results = results;
  
  logAudit(req.userId, 'BATCH_EXECUTED', { batchId: batch.id, results });
  
  res.json({ message: 'Batch executed', results });
});

// ==================== STAKING ROUTES ====================

app.get('/api/staking', authenticate, requireVerified, (req, res) => {
  const positions = stakingPositions[req.userId] || [];
  const userWallets = wallets[req.userId] || [];
  
  const stakingInfo = positions.map(position => {
    const crypto = CRYPTOS.find(c => c.id === position.cryptoId);
    const currentPrice = SIMULATED_PRICES[position.cryptoId] || 0;
    const totalValue = position.amount * currentPrice;
    const dailyReward = totalValue * (crypto.stakingApy / 100 / 365);
    
    return {
      ...position,
      cryptoName: crypto?.name,
      cryptoSymbol: crypto?.symbol,
      currentPrice,
      totalValue: totalValue.toFixed(2),
      dailyReward: dailyReward.toFixed(6),
      monthlyReward: (dailyReward * 30).toFixed(6),
      apy: crypto?.stakingApy || 0,
      daysStaked: Math.floor((Date.now() - new Date(position.startDate).getTime()) / (1000 * 60 * 60 * 24))
    };
  });
  
  const totalStaked = stakingInfo.reduce((sum, p) => sum + parseFloat(p.totalValue), 0);
  const totalRewards = stakingInfo.reduce((sum, p) => sum + parseFloat(p.claimedRewards || 0) + parseFloat(p.pendingRewards || 0), 0);
  
  res.json({
    positions: stakingInfo,
    totalStaked: totalStaked.toFixed(2),
    totalRewards: totalRewards.toFixed(2),
    availableToStake: userWallets
      .filter(w => CRYPTOS.find(c => c.id === w.cryptoId)?.stakingApy > 0)
      .map(w => ({
        cryptoId: w.cryptoId,
        symbol: w.symbol,
        balance: w.balance,
        stakingApy: CRYPTOS.find(c => c.id === w.cryptoId)?.stakingApy
      }))
  });
});

app.post('/api/staking/stake', authenticate, requireVerified, (req, res) => {
  const { cryptoId, amount, walletId } = req.body;
  
  if (!cryptoId || !amount || !walletId) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  const crypto = CRYPTOS.find(c => c.id === cryptoId);
  if (!crypto || crypto.stakingApy === 0) {
    return res.status(400).json({ error: 'Staking not available for this cryptocurrency' });
  }
  
  const stakeAmount = parseFloat(amount);
  if (isNaN(stakeAmount) || stakeAmount <= 0) {
    return res.status(400).json({ error: 'Invalid amount' });
  }
  
  const wallet = (wallets[req.userId] || []).find(w => w.id === walletId);
  if (!wallet || wallet.balance < stakeAmount) {
    return res.status(400).json({ error: 'Insufficient balance' });
  }
  
  const minStake = crypto.id === 'ethereum' ? 0.01 : crypto.id === 'solana' ? 0.5 : 10;
  if (stakeAmount < minStake) {
    return res.status(400).json({ error: `Minimum stake amount is ${minStake} ${crypto.symbol}` });
  }
  
  wallet.balance -= stakeAmount;
  
  const position = {
    id: uuidv4(),
    cryptoId,
    symbol: crypto.symbol,
    amount: stakeAmount,
    walletId,
    startDate: new Date().toISOString(),
    unlockDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    claimedRewards: 0,
    pendingRewards: 0,
    status: 'active',
    apy: crypto.stakingApy
  };
  
  if (!stakingPositions[req.userId]) stakingPositions[req.userId] = [];
  stakingPositions[req.userId].push(position);
  
  logAudit(req.userId, 'STAKING_STAKED', { cryptoId, amount: stakeAmount, positionId: position.id });
  
  res.status(201).json({ message: 'Stake initiated', position });
});

app.post('/api/staking/unstake', authenticate, requireVerified, (req, res) => {
  const { positionId, amount } = req.body;
  
  const position = (stakingPositions[req.userId] || []).find(p => p.id === positionId);
  if (!position) {
    return res.status(404).json({ error: 'Staking position not found' });
  }
  
  if (position.status !== 'active') {
    return res.status(400).json({ error: 'Position not active' });
  }
  
  const unstakeAmount = amount ? parseFloat(amount) : position.amount;
  if (isNaN(unstakeAmount) || unstakeAmount <= 0 || unstakeAmount > position.amount) {
    return res.status(400).json({ error: 'Invalid amount' });
  }
  
  const wallet = (wallets[req.userId] || []).find(w => w.id === position.walletId);
  if (!wallet) {
    return res.status(404).json({ error: 'Wallet not found' });
  }
  
  // Claim pending rewards first
  const crypto = CRYPTOS.find(c => c.id === position.cryptoId);
  const dailyReward = position.amount * (crypto.stakingApy / 100 / 365);
  const daysStaked = (Date.now() - new Date(position.startDate).getTime()) / (1000 * 60 * 60 * 24);
  const pendingRewards = dailyReward * Math.min(daysStaked, 365);
  
  position.pendingRewards = (parseFloat(position.pendingRewards) + pendingRewards).toFixed(6);
  wallet.balance += parseFloat(position.pendingRewards);
  
  // Process unstake
  position.amount -= unstakeAmount;
  wallet.balance += unstakeAmount;
  
  if (position.amount <= 0) {
    position.status = 'unclaimed';
  }
  
  logAudit(req.userId, 'STAKING_UNSTAKED', { positionId, amount: unstakeAmount });
  
  res.json({ 
    message: 'Unstake initiated', 
    amount: unstakeAmount,
    rewardsClaimed: position.pendingRewards,
    remainingStake: position.amount
  });
});

app.post('/api/staking/claim', authenticate, requireVerified, (req, res) => {
  const { positionId } = req.body;
  
  const position = (stakingPositions[req.userId] || []).find(p => p.id === positionId);
  if (!position) {
    return res.status(404).json({ error: 'Staking position not found' });
  }
  
  const wallet = (wallets[req.userId] || []).find(w => w.id === position.walletId);
  if (!wallet) {
    return res.status(404).json({ error: 'Wallet not found' });
  }
  
  const pendingRewards = parseFloat(position.pendingRewards);
  if (pendingRewards <= 0) {
    return res.status(400).json({ error: 'No rewards to claim' });
  }
  
  wallet.balance += pendingRewards;
  position.claimedRewards = (parseFloat(position.claimedRewards) + pendingRewards).toFixed(6);
  position.pendingRewards = 0;
  
  logAudit(req.userId, 'STAKING_CLAIMED', { positionId, amount: pendingRewards });
  
  res.json({ message: 'Rewards claimed', amount: pendingRewards });
});

// ==================== SWAP ROUTES ====================

app.get('/api/swap/rate/:fromCrypto/:toCrypto', authenticate, (req, res) => {
  const { fromCrypto, toCrypto } = req.params;
  
  const from = CRYPTOS.find(c => c.id === fromCrypto);
  const to = CRYPTOS.find(c => c.id === toCrypto);
  
  if (!from || !to) {
    return res.status(404).json({ error: 'Cryptocurrency not found' });
  }
  
  const fromPrice = SIMULATED_PRICES[fromCrypto];
  const toPrice = SIMULATED_PRICES[toCrypto];
  
  // Simulated swap rate with small spread
  const baseRate = fromPrice / toPrice;
  const spread = 0.003; // 0.3% spread
  const rate = baseRate * (1 - spread);
  const inverseRate = 1 / rate;
  
  res.json({
    fromCrypto: { id: fromCrypto, symbol: from.symbol, name: from.name },
    toCrypto: { id: toCrypto, symbol: to.symbol, name: to.name },
    rate: rate.toFixed(8),
    inverseRate: inverseRate.toFixed(8),
    spread: '0.3%',
    estimatedTime: '1-5 minutes',
    minAmount: from.id === 'bitcoin' ? 0.001 : from.id === 'ethereum' ? 0.01 : 1,
    maxAmount: from.id === 'bitcoin' ? 10 : from.id === 'ethereum' ? 100 : 10000
  });
});

app.post('/api/swap/execute', authenticate, requireVerified, (req, res) => {
  const { fromCryptoId, toCryptoId, fromAmount, toAddress } = req.body;
  
  if (!fromCryptoId || !toCryptoId || !fromAmount) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  const fromCrypto = CRYPTOS.find(c => c.id === fromCryptoId);
  const toCrypto = CRYPTOS.find(c => c.id === toCryptoId);
  
  if (!fromCrypto || !toCrypto) {
    return res.status(404).json({ error: 'Cryptocurrency not found' });
  }
  
  const fromWallet = (wallets[req.userId] || []).find(w => w.cryptoId === fromCryptoId);
  if (!fromWallet || fromWallet.balance < parseFloat(fromAmount)) {
    return res.status(400).json({ error: 'Insufficient balance' });
  }
  
  const fromPrice = SIMULATED_PRICES[fromCryptoId];
  const toPrice = SIMULATED_PRICES[toCryptoId];
  const rate = (fromPrice / toPrice) * 0.997; // 0.3% spread
  const toAmount = (parseFloat(fromAmount) * rate).toFixed(toCrypto.decimals);
  
  fromWallet.balance -= parseFloat(fromAmount);
  
  let toWallet = (wallets[req.userId] || []).find(w => w.cryptoId === toCryptoId);
  if (!toWallet) {
    toWallet = {
      id: uuidv4(),
      cryptoId: toCryptoId,
      symbol: toCrypto.symbol,
      name: toCrypto.name,
      address: generateAddress(toCryptoId),
      balance: 0,
      createdAt: new Date().toISOString()
    };
    if (!wallets[req.userId]) wallets[req.userId] = [];
    wallets[req.userId].push(toWallet);
  }
  
  toWallet.balance += parseFloat(toAmount);
  
  const swap = {
    id: uuidv4(),
    fromCryptoId,
    fromSymbol: fromCrypto.symbol,
    toCryptoId,
    toSymbol: toCrypto.symbol,
    fromAmount: parseFloat(fromAmount),
    toAmount: parseFloat(toAmount),
    rate: rate.toFixed(8),
    fee: (parseFloat(fromAmount) * 0.003).toFixed(fromCrypto.decimals),
    status: 'completed',
    timestamp: new Date().toISOString()
  };
  
  if (!swapHistory[req.userId]) swapHistory[req.userId] = [];
  swapHistory[req.userId].push(swap);
  
  logAudit(req.userId, 'SWAP_EXECUTED', { fromCryptoId, toCryptoId, fromAmount, toAmount });
  
  res.json({ message: 'Swap completed', swap });
});

app.get('/api/swap/history', authenticate, requireVerified, (req, res) => {
  const history = swapHistory[req.userId] || [];
  res.json(history);
});

// ==================== MULTI-SIGNATURE WALLET ROUTES ====================

app.post('/api/multisig/create', authenticate, requireVerified, (req, res) => {
  const { name, requiredSigners, totalSigners, description } = req.body;
  
  if (!name || !requiredSigners || !totalSigners || requiredSigners > totalSigners) {
    return res.status(400).json({ error: 'Invalid multisig parameters' });
  }
  
  if (requiredSigners < 1 || totalSigners > 10) {
    return res.status(400).json({ error: 'Invalid signer configuration' });
  }
  
  const wallet = {
    id: uuidv4(),
    name,
    description: description || '',
    address: generateAddress('multisig'),
    requiredSigners,
    totalSigners,
    owners: [{ userId: req.userId, name: users.find(u => u.id === req.userId)?.name, role: 'creator' }],
    transactions: [],
    balance: 0,
    createdAt: new Date().toISOString()
  };
  
  if (!multiSigWallets[req.userId]) multiSigWallets[req.userId] = [];
  multiSigWallets[req.userId].push(wallet);
  
  logAudit(req.userId, 'MULTISIG_CREATED', { walletId: wallet.id, requiredSigners, totalSigners });
  
  res.status(201).json({ message: 'Multisig wallet created', wallet });
});

app.get('/api/multisig', authenticate, requireVerified, (req, res) => {
  const multisigs = multiSigWallets[req.userId] || [];
  
  const enrichedMultisigs = multisigs.map(ms => ({
    ...ms,
    pendingTransactions: ms.transactions.filter(t => t.status === 'pending').length,
    confirmations: ms.transactions.reduce((sum, t) => sum + t.confirmations, 0)
  }));
  
  res.json(enrichedMultisigs);
});

app.get('/api/multisig/:id', authenticate, requireVerified, (req, res) => {
  const multisig = (multiSigWallets[req.userId] || []).find(m => m.id === req.params.id);
  if (!multisig) {
    return res.status(404).json({ error: 'Multisig wallet not found' });
  }
  res.json(multisig);
});

app.post('/api/multisig/:id/add-owner', authenticate, requireVerified, (req, res) => {
  const { email, role = 'signer' } = req.body;
  const multisig = (multiSigWallets[req.userId] || []).find(m => m.id === req.params.id);
  
  if (!multisig) {
    return res.status(404).json({ error: 'Multisig wallet not found' });
  }
  
  if (multisig.owners.length >= multisig.totalSigners) {
    return res.status(400).json({ error: 'Maximum signers reached' });
  }
  
  const userToAdd = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!userToAdd) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  if (multisig.owners.find(o => o.userId === userToAdd.id)) {
    return res.status(400).json({ error: 'User already an owner' });
  }
  
  multisig.owners.push({ 
    userId: userToAdd.id, 
    name: userToAdd.name, 
    role,
    addedAt: new Date().toISOString()
  });
  
  logAudit(req.userId, 'MULTISIG_OWNER_ADDED', { multisigId: multisig.id, userId: userToAdd.id });
  
  res.json({ message: 'Owner added', owners: multisig.owners });
});

app.post('/api/multisig/:id/create-tx', authenticate, requireVerified, (req, res) => {
  const { cryptoId, amount, toAddress, description } = req.body;
  const multisig = (multiSigWallets[req.userId] || []).find(m => m.id === req.params.id);
  
  if (!multisig) {
    return res.status(404).json({ error: 'Multisig wallet not found' });
  }
  
  const isOwner = multisig.owners.find(o => o.userId === req.userId);
  if (!isOwner) {
    return res.status(403).json({ error: 'Not an owner of this wallet' });
  }
  
  if (multisig.balance < parseFloat(amount)) {
    return res.status(400).json({ error: 'Insufficient multisig balance' });
  }
  
  const tx = {
    id: uuidv4(),
    cryptoId,
    amount: parseFloat(amount),
    toAddress,
    description: description || '',
    status: 'pending',
    confirmations: 1,
    requiredConfirmations: multisig.requiredSigners,
    signers: [{ userId: req.userId, name: isOwner.name, timestamp: new Date().toISOString() }],
    createdAt: new Date().toISOString()
  };
  
  multisig.transactions.push(tx);
  
  logAudit(req.userId, 'MULTISIG_TX_CREATED', { multisigId: multisig.id, txId: tx.id });
  
  res.status(201).json({ message: 'Transaction created', transaction: tx });
});

app.post('/api/multisig/:walletId/sign/:txId', authenticate, requireVerified, (req, res) => {
  const multisig = (multiSigWallets[req.userId] || []).find(m => m.id === req.params.walletId);
  
  if (!multisig) {
    return res.status(404).json({ error: 'Multisig wallet not found' });
  }
  
  const tx = multisig.transactions.find(t => t.id === req.params.txId);
  if (!tx) {
    return res.status(404).json({ error: 'Transaction not found' });
  }
  
  if (tx.status !== 'pending') {
    return res.status(400).json({ error: 'Transaction already processed' });
  }
  
  const isOwner = multisig.owners.find(o => o.userId === req.userId);
  if (!isOwner) {
    return res.status(403).json({ error: 'Not an owner' });
  }
  
  const alreadySigned = tx.signers.find(s => s.userId === req.userId);
  if (alreadySigned) {
    return res.status(400).json({ error: 'Already signed this transaction' });
  }
  
  tx.signers.push({ userId: req.userId, name: isOwner.name, timestamp: new Date().toISOString() });
  tx.confirmations++;
  
  if (tx.confirmations >= multisig.requiredSigners) {
    tx.status = 'approved';
    tx.executedAt = new Date().toISOString();
    multisig.balance -= tx.amount;
  }
  
  logAudit(req.userId, 'MULTISIG_TX_SIGNED', { multisigId: multisig.id, txId: tx.id, confirmations: tx.confirmations });
  
  res.json({ message: 'Transaction signed', transaction: tx });
});

// ==================== MARKET DATA ====================

app.get('/api/market/overview', authenticate, (req, res) => {
  const marketData = CRYPTOS.map((crypto, index) => {
    const price = SIMULATED_PRICES[crypto.id];
    const change24h = (Math.random() * 10 - 5).toFixed(2);
    const marketCap = price * (1000000000 - index * 50000000);
    const volume24h = marketCap * (0.05 + Math.random() * 0.1);
    
    return {
      id: crypto.id,
      rank: index + 1,
      name: crypto.name,
      symbol: crypto.symbol,
      price,
      change24h,
      marketCap,
      volume24h,
      circulatingSupply: 1000000000 - index * 50000000,
      maxSupply: crypto.id === 'bitcoin' ? 21000000 : 1000000000,
      stakingApy: crypto.stakingApy
    };
  });
  
  const totalMarketCap = marketData.reduce((sum, c) => sum + c.marketCap, 0);
  const btcDominance = (marketData[0].marketCap / totalMarketCap * 100).toFixed(1);
  
  res.json({
    totalMarketCap,
    btcDominance,
    ethDominance: (marketData[1].marketCap / totalMarketCap * 100).toFixed(1),
    altDominance: (100 - parseFloat(btcDominance) - 5).toFixed(1),
    totalVolume24h: marketData.reduce((sum, c) => sum + c.volume24h, 0),
    marketCapChange24h: (Math.random() * 5 - 2).toFixed(2),
    data: marketData
  });
});

app.get('/api/market/chart/:cryptoId', authenticate, (req, res) => {
  const { cryptoId } = req.params;
  const { days = '30' } = req.query;
  
  const crypto = CRYPTOS.find(c => c.id === cryptoId);
  if (!crypto) {
    return res.status(404).json({ error: 'Cryptocurrency not found' });
  }
  
  const currentPrice = SIMULATED_PRICES[cryptoId];
  const numDays = parseInt(days);
  const data = [];
  
  for (let i = numDays; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    const volatility = 0.02;
    const randomChange = (Math.random() - 0.5) * 2 * volatility;
    const priceChange = currentPrice * (randomChange * (i / numDays));
    const price = Math.max(currentPrice + priceChange, currentPrice * 0.5);
    
    data.push({
      date: date.toISOString().split('T')[0],
      price: price.toFixed(2),
      volume: (price * 1000000 * (0.5 + Math.random())).toFixed(0),
      marketCap: (price * 1000000000).toFixed(0)
    });
  }
  
  res.json({
    cryptoId,
    symbol: crypto.symbol,
    name: crypto.name,
    currentPrice,
    data
  });
});

app.get('/api/market/trending', authenticate, (req, res) => {
  const trending = CRYPTOS.slice(0, 5).map(c => ({
    ...c,
    price: SIMULATED_PRICES[c.id],
    change24h: (Math.random() * 15 - 5).toFixed(2),
    socialScore: Math.floor(Math.random() * 100),
    sentiment: Math.random() > 0.5 ? 'Bullish' : 'Bearish'
  }));
  
  res.json({ trending });
});

app.get('/api/market/gainers-losers', authenticate, (req, res) => {
  const sorted = [...CRYPTOS].sort(() => Math.random() - 0.5);
  const gainers = sorted.slice(0, 3).map(c => ({
    ...c,
    price: SIMULATED_PRICES[c.id],
    change24h: (Math.random() * 15 + 5).toFixed(2)
  }));
  
  const losers = sorted.slice(-3).map(c => ({
    ...c,
    price: SIMULATED_PRICES[c.id],
    change24h: (Math.random() * -15 - 5).toFixed(2)
  }));
  
  res.json({ gainers, losers });
});

// ==================== ALERTS ROUTES ====================

app.get('/api/alerts', authenticate, requireVerified, (req, res) => {
  const alerts = priceAlerts[req.userId] || [];
  res.json(alerts);
});

app.post('/api/alerts', authenticate, requireVerified, (req, res) => {
  const { cryptoId, targetPrice, condition, description } = req.body;
  
  if (!cryptoId || !targetPrice || !condition) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  const crypto = CRYPTOS.find(c => c.id === cryptoId);
  if (!crypto) {
    return res.status(400).json({ error: 'Invalid cryptocurrency' });
  }
  
  const alert = {
    id: uuidv4(),
    cryptoId,
    symbol: crypto.symbol,
    targetPrice: parseFloat(targetPrice),
    condition,
    description: description || `${crypto.symbol} ${condition} $${targetPrice}`,
    status: 'active',
    triggeredAt: null,
    createdAt: new Date().toISOString(),
    notifications: { email: true, push: true }
  };
  
  if (!priceAlerts[req.userId]) priceAlerts[req.userId] = [];
  priceAlerts[req.userId].push(alert);
  
  logAudit(req.userId, 'ALERT_CREATED', { cryptoId, targetPrice, condition });
  
  res.status(201).json({ message: 'Alert created', alert });
});

app.put('/api/alerts/:id', authenticate, requireVerified, (req, res) => {
  const alert = (priceAlerts[req.userId] || []).find(a => a.id === req.params.id);
  
  if (!alert) {
    return res.status(404).json({ error: 'Alert not found' });
  }
  
  Object.assign(alert, req.body, { updatedAt: new Date().toISOString() });
  res.json({ message: 'Alert updated', alert });
});

app.delete('/api/alerts/:id', authenticate, requireVerified, (req, res) => {
  const alerts = priceAlerts[req.userId] || [];
  const index = alerts.findIndex(a => a.id === req.params.id);
  
  if (index === -1) {
    return res.status(404).json({ error: 'Alert not found' });
  }
  
  alerts.splice(index, 1);
  logAudit(req.userId, 'ALERT_DELETED', { alertId: req.params.id });
  
  res.json({ message: 'Alert deleted' });
});

// ==================== ADDRESS BOOK ROUTES ====================

app.get('/api/address-book', authenticate, (req, res) => {
  const addresses = addressBook[req.userId] || [];
  res.json(addresses);
});

app.post('/api/address-book', authenticate, (req, res) => {
  const { name, address, cryptoId, memo } = req.body;
  
  if (!name || !address || !cryptoId) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  const entry = {
    id: uuidv4(),
    name,
    address,
    cryptoId,
    memo: memo || '',
    createdAt: new Date().toISOString()
  };
  
  if (!addressBook[req.userId]) addressBook[req.userId] = [];
  addressBook[req.userId].push(entry);
  
  res.status(201).json({ message: 'Address added', entry });
});

app.delete('/api/address-book/:id', authenticate, (req, res) => {
  const addresses = addressBook[req.userId] || [];
  const index = addresses.findIndex(a => a.id === req.params.id);
  
  if (index === -1) {
    return res.status(404).json({ error: 'Address not found' });
  }
  
  addresses.splice(index, 1);
  res.json({ message: 'Address deleted' });
});

// ==================== ADMIN ROUTES ====================

app.get('/api/admin/stats', authenticate, requireAdmin, (req, res) => {
  const totalUsers = users.length;
  const totalWallets = Object.values(wallets).reduce((sum, uw) => sum + uw.length, 0);
  const totalTransactions = Object.values(transactions).reduce((sum, ut) => sum + ut.length, 0);
  const totalVolume = Object.values(transactions)
    .flat()
    .reduce((sum, t) => sum + (t.amount || 0), 0);
  
  res.json({
    totalUsers,
    totalWallets,
    totalTransactions,
    totalVolume: totalVolume.toFixed(2),
    activeUsers: Math.floor(totalUsers * 0.7),
    newUsersToday: Math.floor(totalUsers * 0.1)
  });
});

app.get('/api/admin/users', authenticate, requireAdmin, (req, res) => {
  const { page = 1, limit = 20 } = req.query;
  const start = (page - 1) * limit;
  
  const usersList = users.map(u => {
    const { password: _, verificationToken: __, twoFactorSecret: ___, ...safeUser } = u;
    return safeUser;
  });
  
  res.json({
    users: usersList.slice(start, start + parseInt(limit)),
    total: users.length
  });
});

app.get('/api/admin/logs', authenticate, requireAdmin, (req, res) => {
  const { page = 1, limit = 50 } = req.query;
  const start = (page - 1) * limit;
  
  res.json({
    logs: auditLogs.slice(start, start + parseInt(limit)).reverse(),
    total: auditLogs.length
  });
});

// ==================== ERROR HANDLING ====================

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// ==================== START SERVER ====================

app.listen(PORT, () => {
  console.log(`🚀 CryptoWallet API Server running on port ${PORT}`);
  console.log(`📡 API endpoints available at http://localhost:${PORT}/api`);
  console.log(`🔐 JWT Secret: ${JWT_SECRET.substring(0, 10)}...`);
  console.log(`📊 Supported Cryptocurrencies: ${CRYPTOS.length}`);
});

module.exports = app;
