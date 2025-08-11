const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const PORT = 5000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false
}));

// Mock database
const users = [
    {
        id: 1,
        username: 'john',
        passwordHash: bcrypt.hashSync('password123', 10)
    },
    {
        id: 2,
        username: 'admin',
        passwordHash: bcrypt.hashSync('adminpass', 10)
    }
];

// Helper: generate 6-digit OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Routes
app.get('/', (req, res) => {
    if (req.session.loggedIn) {
        res.send(`
            <h1>Welcome back, ${req.session.username}!</h1>
            <p><a href="/logout">Logout</a></p>
        `);
    } else if (req.session.pendingOTP) {
        res.redirect('/verify-otp');
    } else {
        res.sendFile(path.join(__dirname, 'public', 'login.html'));
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (user && await bcrypt.compare(password, user.passwordHash)) {
        // Step 1: Generate OTP
        const otp = generateOTP();

        // Step 2: Store OTP in session
        req.session.pendingOTP = otp;
        req.session.userId = user.id;
        req.session.username = user.username;

        // Step 3: Send OTP (here we just log it; in production, send via email/SMS)
        console.log(`OTP for ${username}: ${otp}`);

        res.redirect('/verify-otp');
    } else {
        res.send(`
            <h1>Login Failed</h1>
            <p>Invalid credentials. <a href="/">Try again</a></p>
        `);
    }
});

app.get('/verify-otp', (req, res) => {
    if (!req.session.pendingOTP) return res.redirect('/');

    res.send(`
        <h1>Enter OTP</h1>
        <form action="/verify-otp" method="post">
            <input type="text" name="otp" placeholder="Enter OTP" required />
            <button type="submit">Verify</button>
        </form>
    `);
});

app.post('/verify-otp', (req, res) => {
    const { otp } = req.body;

    if (otp === req.session.pendingOTP) {
        req.session.loggedIn = true;
        delete req.session.pendingOTP; // clear OTP after success
        res.redirect('/');
    } else {
        res.send(`
            <h1>Invalid OTP</h1>
            <p><a href="/verify-otp">Try again</a></p>
        `);
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        res.redirect('/');
    });
});

app.listen(5000, () => {
    console.log(`Server running on http://localhost:${5000}`);
});
