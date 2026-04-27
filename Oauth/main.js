const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const fs = require('fs');
const path = require('path');
const setupOAuth = require('./oAuth/Oauth');

const app = express();
app.use(express.json());
app.use(cors());

// Configuration
const SECRET_KEY = "your_secret_key_here";
const DB_PATH = path.join(__dirname, 'DB', 'users.json');

// --- DATABASE LOGIC ---
let users = [];
const loadData = () => {
    try {
        if (fs.existsSync(DB_PATH)) {
            users = JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
        }
    } catch (err) { console.error("DB Load Error:", err); }
};

const saveUsersToFile = (data) => {
    try {
        fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
    } catch (err) { console.error("DB Save Error:", err); }
};

loadData(); // Initial load

// --- OAUTH INTEGRATION ---
// Pass dependencies to OAuth module
setupOAuth(app, users, SECRET_KEY, saveUsersToFile);

// --- AUTH MIDDLEWARE ---
const authenticateJWT = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(403).json({ message: "Token missing" });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ message: "Invalid token" });
        
        const user = users.find(u => u.id === decoded.id);
        if (!user) return res.status(404).json({ message: "User not found" });
        
        req.user = user; 
        next();
    });
};

// --- ROUTES ---

// 1. Auth & Identity
app.post("/login", (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (user && bcrypt.compareSync(password, user.password)) {
        const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: "1h" });
        return res.json({ token });
    }
    res.status(401).json({ message: "Invalid credentials" });
});

app.get("/account/balance", authenticateJWT, (req, res) => {
    res.json({ username: req.user.username, balance: req.user.balance });
});

// 2. Transactions
app.post("/account/deposit", authenticateJWT, (req, res) => {
    const { amount } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ message: "Invalid amount" });

    req.user.balance += Number(amount);
    req.user.transactions.unshift({
        type: "DEPOSIT",
        amount: Number(amount),
        date: new Date().toISOString()
    });

    saveUsersToFile(users);
    res.json({ message: "Deposit successful", newBalance: req.user.balance });
});

app.post("/account/transfer", authenticateJWT, (req, res) => {
    const { toUsername, amount } = req.body;
    const recipient = users.find(u => u.username === toUsername);

    if (!recipient || amount <= 0 || req.user.balance < amount) {
        return res.status(400).json({ message: "Transfer failed: Check recipient or funds" });
    }

    req.user.balance -= Number(amount);
    recipient.balance += Number(amount);

    const timestamp = new Date().toISOString();
    req.user.transactions.unshift({ type: "TRANSFER_OUT", to: toUsername, amount: Number(amount), date: timestamp });
    recipient.transactions.unshift({ type: "TRANSFER_IN", from: req.user.username, amount: Number(amount), date: timestamp });

    saveUsersToFile(users);
    res.json({ message: "Transfer successful", currentBalance: req.user.balance });
});

app.get("/account/transactions", authenticateJWT, (req, res) => {
    res.json(req.user.transactions);
});

app.listen(5000, () => console.log("Bank Server running on http://localhost:5000"));
