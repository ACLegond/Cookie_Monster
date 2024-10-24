const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const cookieParser = require('cookie-parser');  // Add this

const app = express();
const db = new sqlite3.Database(':memory:');

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());  // Add this
app.use(session({
    secret: 'supersecret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using https
}));

// Create users table if not exists
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )`);
});

// EJS setup
app.set('view engine', 'ejs');

// Routes
app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    const { username, password } = req.cookies;

    // Pre-fill the login form if the cookies exist
    res.render('login', {
        message: null,
        savedUsername: username || '',
        savedPassword: password || ''
    });
});

app.get('/register', (req, res) => {
    res.render('register', { message: null });
});

// Handle registration
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Check if the user already exists
    db.get('SELECT username FROM users WHERE username = ?', [username], (err, row) => {
        if (row) {
            return res.render('register', { message: 'Username already exists' });
        }

        // Hash the password
        const saltRounds = 10;
        bcrypt.hash(password, saltRounds, (err, hash) => {
            // Store the user in the database
            db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], (err) => {
                if (err) {
                    return res.render('register', { message: 'Error occurred' });
                }
                res.redirect('/login');
            });
        });
    });
});

// Handle login
app.post('/login', (req, res) => {
    const { username, password, remember } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (!user) {
            return res.render('login', { message: 'Invalid username or password', savedUsername: '', savedPassword: '' });
        }

        bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                req.session.username = username;

                // If "Remember Me" is checked, store username and password in cookies for 24 hours
                if (remember) {
                    res.cookie('username', username, { maxAge: 24 * 60 * 60 * 1000, httpOnly: true });
                    res.cookie('password', password, { maxAge: 24 * 60 * 60 * 1000, httpOnly: true });  // In practice, password should be encrypted
                }

                res.redirect('/dashboard');
            } else {
                res.render('login', { message: 'Invalid username or password', savedUsername: '', savedPassword: '' });
            }
        });
    });
});

app.get('/dashboard', (req, res) => {
    if (req.session.username) {
        res.send(`Hello, ${req.session.username}!`);
    } else {
        res.redirect('/login');
    }
});

// Start the server
app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
});
