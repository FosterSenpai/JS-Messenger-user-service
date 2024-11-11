// === Imports ===
const express = require('express');
const cors = require('cors');
const app = express();
const pool = require('./db');
const bcrypt = require('bcrypt'); // For password hashing.

// === Middleware ===
app.use(cors());         // Use cors to allow cross-origin requests.
app.use(express.json()); // Parse request as JSON.

// === Routes ===
// Set Cache-Control header.
app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
});

// Route to register a new user.
app.post("/api/users", async (req, res) => {
    try {
        const { username, password, city, region, country } = req.body; // Destructure the username, password, and location from the request body.
        
            
        console.log('Login request received:', { username, password });


        // Check if the username already exists
        const [existingUser] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        if (existingUser.length > 0) {
            return res.status(400).json({ success: false, message: 'Username already taken' });
        }

        const hashedPassword = await bcrypt.hash(password, 10); // Hash the password

        // Insert the username, hashed password, and location into the users table.
        const [result] = await pool.query('INSERT INTO users (username, password, city, region, country) VALUES (?, ?, ?, ?, ?)', [username, hashedPassword, city, region, country]);
        res.json({ id: result.insertId, username, city, region, country }); // Send the response as JSON.

    } catch (err) { // Catch any errors.
        console.error(err.message);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

// Route to login a user.
app.post("/api/login", async (req, res) => {
    try {
        const { username, password } = req.body; // Destructure the username and password from the request body.
        // Select the user from the users table.
        const [user] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);

        if (user.length === 0) { // If the user does not exist.
            return res.status(404).json({ success: false, message: 'User not found' }); // Send a 404 response.
        }

        const validPassword = await bcrypt.compare(password, user[0].password); // Compare the password with the hashed password
        if (!validPassword) { // If the password is invalid.
            return res.status(401).json({ success: false, message: 'Invalid password' }); // Send a 401 response.
        }

        res.json({ success: true, message: 'Login successful' }); // Send a success response.

    } catch (err) { // Catch any errors.
        console.error(err.message);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

// Route to get all users.
app.get("/api/users", async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM users'); // Select all users from the users table.
        res.json(rows);
    } catch (err) { // Catch any errors.
        console.error(err.message);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

// Route to get a user by username
app.get("/api/users/:username", async (req, res) => {
    try {
        const { username } = req.params; // Destructure the username from the request parameters.

        // Select the user from the users table.
        const [user] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);

        if (user.length === 0) { // If the user does not exist.
            return res.status(404).json({ success: false, message: 'User not found' }); // Send a 404 response.
        }

        res.json(user[0]); // Send the user data as JSON.
        
    } catch (err) { // Catch any errors.
        console.error(err.message);
        res.status(500).json({ success: false, message: 'Server Error' }); // Return JSON error response
    }
});

// === Server ===
// Listen on port 5001.
app.listen(5001, () => {
    console.log('User Service is running on port 5001');
});