const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'halal-trading-secret-key-change-in-production';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';

// ==================== DATA DIRECTORIES ====================
const dataDir = path.join(__dirname, 'data');
const tradesDir = path.join(dataDir, 'trades');
const pendingDir = path.join(dataDir, 'pending');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(tradesDir)) fs.mkdirSync(tradesDir);
if (!fs.existsSync(pendingDir)) fs.mkdirSync(pendingDir);

const usersFile = path.join(dataDir, 'users.json');
const pendingFile = path.join(pendingDir, 'pending_users.json');

// Default owner account
if (!fs.existsSync(usersFile)) {
    const defaultUsers = {
        "mujtabahatif@gmail.com": {
            email: "mujtabahatif@gmail.com",
            password: bcrypt.hashSync("Mujtabah@2598", 10),
            isOwner: true,
            isApproved: true,
            isBlocked: false,
            apiKey: "",
            secretKey: "",
            createdAt: new Date().toISOString()
        }
    };
    fs.writeFileSync(usersFile, JSON.stringify(defaultUsers, null, 2));
}

if (!fs.existsSync(pendingFile)) {
    fs.writeFileSync(pendingFile, JSON.stringify({}));
}

function readUsers() { return JSON.parse(fs.readFileSync(usersFile)); }
function writeUsers(users) { fs.writeFileSync(usersFile, JSON.stringify(users, null, 2)); }
function readPending() { return JSON.parse(fs.readFileSync(pendingFile)); }
function writePending(pending) { fs.writeFileSync(pendingFile, JSON.stringify(pending, null, 2)); }

// Encryption helpers
function encrypt(text) {
    if (!text) return "";
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}
function decrypt(text) {
    if (!text) return "";
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ==================== AUTHENTICATION ====================
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
    const users = readUsers();
    if (users[email]) return res.status(400).json({ success: false, message: 'User already exists' });
    const pending = readPending();
    if (pending[email]) return res.status(400).json({ success: false, message: 'Request already pending' });
    const hashedPassword = bcrypt.hashSync(password, 10);
    pending[email] = { email, password: hashedPassword, requestedAt: new Date().toISOString(), status: 'pending' };
    writePending(pending);
    res.json({ success: true, message: 'Registration request sent to owner.' });
});

app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const pending = readPending();
    const list = Object.keys(pending).map(email => ({ email, requestedAt: pending[email].requestedAt }));
    res.json({ success: true, pending: list });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    const users = readUsers();
    users[email] = {
        email, password: pending[email].password,
        isOwner: false, isApproved: true, isBlocked: false,
        apiKey: "", secretKey: "",
        approvedAt: new Date().toISOString(),
        createdAt: pending[email].requestedAt
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} approved.` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} rejected.` });
});

app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: 'Email required' });
    const users = readUsers();
    if (!users[email]) return res.status(404).json({ success: false, message: 'User not found' });
    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);
    res.json({ success: true, message: `User ${email} is now ${users[email].isBlocked ? 'blocked' : 'unblocked'}.` });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const users = readUsers();
    const user = users[email];
    if (!user) {
        const pending = readPending();
        if (pending[email]) return res.status(401).json({ success: false, message: 'Pending approval' });
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!user.isApproved && !user.isOwner) return res.status(401).json({ success: false, message: 'Account not approved' });
    if (user.isBlocked) return res.status(401).json({ success: false, message: 'Your account has been blocked by the owner.' });
    const token = jwt.sign({ email, isOwner: user.isOwner || false }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, isOwner: user.isOwner || false });
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ success: false, message: 'No token' });
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// ==================== API KEY MANAGEMENT & CONNECTION ====================
function cleanKey(key) {
    if (!key) return "";
    return key.replace(/[\s\n\r\t]+/g, '').trim();
}

async function testBinanceConnection(apiKey, secretKey) {
    const timeResponse = await axios.get('https://api.binance.com/api/v3/time', { timeout: 5000 });
    const timestamp = timeResponse.data.serverTime;
    const queryString = `recvWindow=5000&timestamp=${timestamp}`;
    const signature = crypto.createHmac('sha256', secretKey).update(queryString).digest('hex');
    const url = `https://api.binance.com/api/v3/account?${queryString}&signature=${signature}`;
    const response = await axios.get(url, {
        headers: { 'X-MBX-APIKEY': apiKey },
        timeout: 10000
    });
    return response.data;
}

app.post('/api/set-api-keys', authenticate, async (req, res) => {
    let { apiKey, secretKey } = req.body;
    if (!apiKey || !secretKey) return res.status(400).json({ success: false, message: 'Both API key and secret key required' });
    const cleanApi = cleanKey(apiKey);
    const cleanSecret = cleanKey(secretKey);
    if (!cleanApi || !cleanSecret) return res.status(400).json({ success: false, message: 'Invalid API key format. Remove spaces and line breaks.' });
    try {
        const accountData = await testBinanceConnection(cleanApi, cleanSecret);
        if (!accountData.canTrade) return res.status(401).json({ success: false, message: 'Please enable "Spot & Margin Trading" in your Binance API settings.' });
        const users = readUsers();
        if (!users[req.user.email]) return res.status(404).json({ success: false, message: 'User not found' });
        users[req.user.email].apiKey = encrypt(cleanApi);
        users[req.user.email].secretKey = encrypt(cleanSecret);
        writeUsers(users);
        res.json({ success: true, message: 'API keys saved successfully!' });
    } catch (error) {
        let errorMessage = 'Invalid Binance API keys. ';
        if (error.response?.data?.code === -2015) errorMessage += 'API key format invalid or permissions missing. Enable "Spot & Margin Trading".';
        else if (error.response?.data?.code === -1021) errorMessage += 'Timestamp error. Server time sync issue.';
        else if (error.response?.data?.code === -1022) errorMessage += 'Signature error. Check that your Secret Key is correct.';
        else if (error.response?.status === 401) errorMessage += 'Invalid API key or secret key. Check for typos.';
        else errorMessage += error.response?.data?.msg || error.message;
        res.status(401).json({ success: false, message: errorMessage });
    }
});

// NEW: Connect to Binance and get balance
app.post('/api/connect-binance', authenticate, async (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.status(400).json({ success: false, message: 'No API keys saved. Please save your API keys first.' });
    
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    
    try {
        const accountData = await testBinanceConnection(apiKey, secretKey);
        const usdtBalance = accountData.balances.find(b => b.asset === 'USDT');
        const balance = parseFloat(usdtBalance?.free || 0);
        
        res.json({
            success: true,
            balance: balance,
            canTrade: accountData.canTrade,
            message: `Connected! Balance: ${balance} USDT`
        });
    } catch (error) {
        let errorMessage = 'Connection failed. ';
        if (error.response?.data?.code === -2015) errorMessage += 'Invalid API key or missing permissions.';
        else if (error.response?.data?.code === -1022) errorMessage += 'Invalid secret key.';
        else errorMessage += error.response?.data?.msg || error.message;
        res.status(401).json({ success: false, message: errorMessage });
    }
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.json({ success: false, message: 'No API keys set' });
    res.json({ success: true, apiKey: decrypt(user.apiKey), secretKey: decrypt(user.secretKey) });
});

// ==================== AI TRADING ENGINE ====================
const winStreaks = {};
class AITradingEngine {
    analyzeMarket(symbol, marketData, sessionId) {
        const { price = 0, volume24h = 0, priceChange24h = 0, high24h = 0, low24h = 0 } = marketData;
        const volumeRatio = volume24h / 1000000;
        const pricePosition = high24h > low24h ? (price - low24h) / (high24h - low24h) : 0.5;
        let confidence = 0.7;
        if (volumeRatio > 1.3) confidence += 0.15;
        if (volumeRatio > 1.8) confidence += 0.2;
        if (priceChange24h > 3) confidence += 0.2;
        if (priceChange24h > 7) confidence += 0.25;
        if (pricePosition < 0.35) confidence += 0.15;
        if (pricePosition > 0.65) confidence += 0.15;
        const currentStreak = winStreaks[sessionId] || 0;
        if (currentStreak > 0) confidence += (currentStreak * 0.05);
        confidence = Math.min(confidence, 0.98);
        const action = (pricePosition < 0.35 && priceChange24h > -3 && volumeRatio > 1.1) ? 'BUY' :
                      (pricePosition > 0.65 && priceChange24h > 3 && volumeRatio > 1.1) ? 'SELL' : 
                      (Math.random() > 0.2 ? 'BUY' : 'SELL');
        return { symbol, price, confidence, action };
    }
    calculatePositionSize(initialInvestment, currentProfit, targetProfit, timeElapsed, timeLimit, confidence, sessionId) {
        const timeRemaining = Math.max(0.1, (timeLimit - timeElapsed) / timeLimit);
        const remainingProfit = Math.max(1, targetProfit - currentProfit);
        let baseSize = Math.max(10, initialInvestment * 0.25);
        const timePressure = 1.5 / timeRemaining;
        const targetPressure = remainingProfit / (initialInvestment * 3);
        const currentStreak = winStreaks[sessionId] || 0;
        const winBonus = 1 + (currentStreak * 0.3);
        let positionSize = baseSize * timePressure * targetPressure * confidence * winBonus;
        const maxPosition = initialInvestment * 4;
        positionSize = Math.min(positionSize, maxPosition);
        positionSize = Math.max(positionSize, 10);
        return positionSize;
    }
}

// ==================== BINANCE API FOR TRADING ====================
const rateLimit = { lastRequestTime: 0, lastOrderTime: 0, bannedUntil: 0, warningCount: 0, timeOffset: 0, lastTimeSync: 0 };
class BinanceAPI {
    static endpoints = { base: ['https://api.binance.com', 'https://api1.binance.com', 'https://api2.binance.com', 'https://api3.binance.com', 'https://api4.binance.com'], data: ['https://data.binance.com'], testnet: ['https://testnet.binance.vision'] };
    static async delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
    static async getServerTime() { const response = await axios.get('https://api.binance.com/api/v3/time'); return response.data.serverTime; }
    static generateSignature(queryString, secret) { return crypto.createHmac('sha256', secret).update(queryString).digest('hex'); }
    static async makeRequest(endpoint, method, apiKey, secret, params = {}, useTestnet = false) {
        const timeSinceLast = Date.now() - rateLimit.lastRequestTime;
        if (timeSinceLast < 1500) await this.delay(1500 - timeSinceLast);
        rateLimit.lastRequestTime = Date.now();
        const timestamp = await this.getServerTime();
        const queryParams = { ...params, timestamp, recvWindow: 10000 };
        const sortedKeys = Object.keys(queryParams).sort();
        const queryString = sortedKeys.map(k => `${k}=${queryParams[k]}`).join('&');
        const signature = this.generateSignature(queryString, secret);
        const baseUrl = useTestnet ? this.endpoints.testnet[0] : this.endpoints.base[0];
        const url = `${baseUrl}${endpoint}?${queryString}&signature=${signature}`;
        const response = await axios({ method, url, headers: { 'X-MBX-APIKEY': apiKey }, timeout: 10000 });
        return response.data;
    }
    static async getAccountBalance(apiKey, secret, useTestnet = false) {
        try {
            const data = await this.makeRequest('/api/v3/account', 'GET', apiKey, secret, {}, useTestnet);
            const usdtBalance = data.balances.find(b => b.asset === 'USDT');
            return { success: true, free: parseFloat(usdtBalance?.free || 0), total: parseFloat(usdtBalance?.free || 0) };
        } catch (error) { return { success: false, error: error.message }; }
    }
    static async getTicker(symbol, useTestnet = false) {
        try {
            const baseUrl = useTestnet ? this.endpoints.testnet[0] : this.endpoints.data[0];
            const response = await axios.get(`${baseUrl}/api/v3/ticker/24hr?symbol=${symbol}`, { timeout: 5000 });
            return { success: true, data: response.data };
        } catch (error) { return { success: false, error: error.message }; }
    }
    static async placeMarketOrder(apiKey, secret, symbol, side, quoteOrderQty, useTestnet = false) {
        try {
            const orderData = await this.makeRequest('/api/v3/order', 'POST', apiKey, secret, { symbol, side, type: 'MARKET', quoteOrderQty: quoteOrderQty.toFixed(2) }, useTestnet);
            let avgPrice = 0;
            if (orderData.fills && orderData.fills.length > 0) {
                let totalValue = 0, totalQty = 0;
                orderData.fills.forEach(fill => { totalValue += parseFloat(fill.price) * parseFloat(fill.qty); totalQty += parseFloat(fill.qty); });
                avgPrice = totalValue / totalQty;
            }
            return { success: true, orderId: orderData.orderId, executedQty: parseFloat(orderData.executedQty), price: avgPrice };
        } catch (error) { return { success: false, error: error.message }; }
    }
}

const aiEngine = new AITradingEngine();
const userTradingState = {};

// ==================== TRADING ENDPOINTS ====================
app.post('/api/start-trading', authenticate, async (req, res) => {
    const { initialInvestment, targetProfit, timeLimit, riskLevel, tradingPairs } = req.body;
    const users = readUsers();
    const user = users[req.user.email];
    if (!user.apiKey) return res.status(400).json({ success: false, message: 'Please add your Binance API keys first' });
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const balance = await BinanceAPI.getAccountBalance(apiKey, secretKey, false);
    if (!balance.success || balance.free < initialInvestment) return res.status(400).json({ success: false, message: `Insufficient balance. Need $${initialInvestment}` });
    const botId = 'bot_' + Date.now() + '_' + req.user.email.replace(/[^a-z0-9]/gi, '_');
    userTradingState[req.user.email] = { botId, initialInvestment, targetProfit, timeLimit, riskLevel, tradingPairs, startedAt: Date.now(), isRunning: true, currentProfit: 0, trades: [], lastTradeTime: Date.now() };
    winStreaks[req.user.email] = 0;
    res.json({ success: true, botId });
});
app.post('/api/stop-trading', authenticate, (req, res) => { if (userTradingState[req.user.email]) userTradingState[req.user.email].isRunning = false; res.json({ success: true }); });
app.post('/api/trading-update', authenticate, async (req, res) => {
    const state = userTradingState[req.user.email];
    if (!state || !state.isRunning) return res.json({ success: true, currentProfit: 0, newTrades: [] });
    const users = readUsers();
    const user = users[req.user.email];
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const newTrades = [];
    const now = Date.now();
    const timeElapsed = (now - state.startedAt) / (1000 * 60 * 60);
    const timeRemaining = Math.max(0, state.timeLimit - timeElapsed);
    const timeSinceLastTrade = (now - (state.lastTradeTime || 0)) / 1000;
    if (timeRemaining > 0 && timeSinceLastTrade >= 90) {
        const symbol = state.tradingPairs[Math.floor(Math.random() * state.tradingPairs.length)] || 'BTCUSDT';
        const tickerData = await BinanceAPI.getTicker(symbol, false);
        if (tickerData.success) {
            const marketPrice = parseFloat(tickerData.data.lastPrice);
            const marketData = { price: marketPrice, volume24h: parseFloat(tickerData.data.volume), priceChange24h: parseFloat(tickerData.data.priceChangePercent), high24h: parseFloat(tickerData.data.highPrice), low24h: parseFloat(tickerData.data.lowPrice) };
            const signal = aiEngine.analyzeMarket(symbol, marketData, req.user.email);
            if (signal.action !== 'HOLD') {
                const positionSize = aiEngine.calculatePositionSize(state.initialInvestment, state.currentProfit, state.targetProfit, timeElapsed, state.timeLimit, signal.confidence, req.user.email);
                const orderResult = await BinanceAPI.placeMarketOrder(apiKey, secretKey, symbol, signal.action, positionSize, false);
                if (orderResult.success) {
                    const currentTicker = await BinanceAPI.getTicker(symbol, false);
                    const currentPrice = currentTicker.success ? parseFloat(currentTicker.data.lastPrice) : marketPrice;
                    const entryPrice = orderResult.price || marketPrice;
                    let profit = signal.action === 'BUY' ? (currentPrice - entryPrice) * orderResult.executedQty : (entryPrice - currentPrice) * orderResult.executedQty;
                    if (profit > 0) winStreaks[req.user.email] = (winStreaks[req.user.email] || 0) + 1;
                    else winStreaks[req.user.email] = 0;
                    state.currentProfit += profit;
                    state.lastTradeTime = now;
                    newTrades.push({ symbol, side: signal.action, quantity: orderResult.executedQty.toFixed(6), price: entryPrice.toFixed(2), profit, size: '$' + positionSize.toFixed(2), confidence: (signal.confidence * 100).toFixed(0) + '%', winStreak: winStreaks[req.user.email], timestamp: new Date().toISOString() });
                    state.trades.unshift(...newTrades);
                    if (state.currentProfit >= state.targetProfit) state.isRunning = false;
                    const userTradeFile = path.join(tradesDir, req.user.email.replace(/[^a-z0-9]/gi, '_') + '.json');
                    let allTrades = [];
                    if (fs.existsSync(userTradeFile)) allTrades = JSON.parse(fs.readFileSync(userTradeFile));
                    allTrades.unshift(...newTrades);
                    fs.writeFileSync(userTradeFile, JSON.stringify(allTrades, null, 2));
                }
            }
        }
    }
    if (timeElapsed >= state.timeLimit) state.isRunning = false;
    const balance = await BinanceAPI.getAccountBalance(apiKey, secretKey, false);
    res.json({ success: true, currentProfit: state.currentProfit || 0, timeRemaining: timeRemaining.toFixed(2), targetReached: state.targetReached || false, timeExceeded: state.timeExceeded || false, newTrades, balance: balance.free, winStreak: winStreaks[req.user.email] || 0 });
});

// ==================== OWNER ADMIN ENDPOINTS ====================
app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const list = Object.keys(users).map(email => ({ email, hasApiKeys: !!users[email].apiKey, isOwner: users[email].isOwner, isApproved: users[email].isApproved, isBlocked: users[email].isBlocked }));
    res.json({ success: true, users: list });
});
app.get('/api/admin/all-trades', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const allTrades = {};
    const files = fs.readdirSync(tradesDir);
    for (const file of files) {
        if (file === '.gitkeep') continue;
        const userId = file.replace('.json', '');
        const trades = JSON.parse(fs.readFileSync(path.join(tradesDir, file)));
        allTrades[userId] = trades;
    }
    res.json({ success: true, trades: allTrades });
});
app.post('/api/change-password', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ success: false, message: 'Current and new password required' });
    const users = readUsers();
    const owner = users[req.user.email];
    if (!bcrypt.compareSync(currentPassword, owner.password)) return res.status(401).json({ success: false, message: 'Current password is incorrect' });
    owner.password = bcrypt.hashSync(newPassword, 10);
    writeUsers(users);
    res.json({ success: true, message: 'Password changed! Please login again.' });
});

app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🌙 Halal AI Trading Bot - FINAL VERSION`);
    console.log(`✅ Owner: mujtabahatif@gmail.com / Mujtabah@2598`);
});
