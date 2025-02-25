require("dotenv").config();
console.log('Environment variables loaded:', process.env);
const express = require("express");
const mysql = require("mysql2/promise");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const crypto = require('crypto');
const nodemailer = require("nodemailer");

const app = express();
app.use(express.json());
app.use(cors());

// Set up MySQL database connection
const pool = mysql.createPool({
    host: "mysql-123456.mysql.database.azure.com",
    user: "demodb",
    password: "GUp8VXUBbzwTx9xQzNPG",
    database: "partner_app",
});

// Use a fixed JWT secret or load it from an environment variable
const JWT_SECRET = process.env.JWT_SECRET;
console.log('Using JWT_SECRET:', JWT_SECRET);

// Middleware to verify JWT and add user info to request
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1];

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                console.log('JWT verification error:', err);
                return res.status(403).json({ message: 'Failed to authenticate token' });
            }

            console.log('Authenticated user:', user);
            req.user = user;
            next();
        });
    } else {
        return res.status(401).json({ message: 'No token provided' });
    }
};

// Function to generate OTP
function generateOtp() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Function to send OTP via email
async function sendOtpEmail(email, otp) {
    const data = {
        recipients: [
            {
                to: [
                    {
                        name: "User", // Change this as needed
                        email: email,
                    },
                ],
                variables: {
                    company_name: "anaxee",
                    otp: otp,
                },
            },
        ],
        from: {
            name: "anaxee",
            email: "noreply@support.anaxee.com",
        },
        domain: "support.anaxee.com",
        template_id: "global_otp",
    };

    try {
        const response = await axios.post(
            "https://control.msg91.com/api/v5/email/send",
            data,
            {
                headers: {
                    accept: "application/json",
                    authkey: "103801ASIjpSVep5dadb6b2", // Keep this secure
                    "content-type": "application/json",
                },
            }
        );
        console.log("OTP sent successfully:", response.data);
    } catch (error) {
        console.error("Error sending OTP:", error);
        throw new Error("Failed to send OTP");
    }
}


// Endpoint to send OTP
app.post("/send-otp", async (req, res) => {
    const { email } = req.body;

    try {
        const otp = generateOtp();
        const expiryTime = new Date(Date.now() + 5 * 60000); // OTP expires in 5 minutes

        await pool.query(
            "INSERT INTO otp (email, otp, expires_at) VALUES (?, ?, ?)",
            [email, otp, expiryTime]
        );

        await sendOtpEmail(email, otp);

        res.status(200).json({ message: "OTP sent successfully" });
    } catch (error) {
        console.error("Error sending OTP:", error);
        res.status(500).json({ message: "Error sending OTP" });
    }
});

// Endpoint to verify OTP
app.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;

    try {
        const [rows] = await pool.query(
            'SELECT * FROM otp WHERE email = ? ORDER BY created_at DESC LIMIT 1',
            [email]
        );
        const latestOtp = rows[0];

        console.log('Latest OTP record:', latestOtp);
        console.log('Entered OTP:', otp);

        if (!latestOtp) {
            console.log('No OTP found for this email');
            return res.status(400).json({ message: 'No OTP found for this email.' });
        }

        const isOtpValid = latestOtp.otp === otp;
        const isOtpExpired = new Date() >= new Date(latestOtp.expires_at);

        console.log('OTP match:', isOtpValid);
        console.log('OTP expired:', isOtpExpired);

        if (isOtpValid && !isOtpExpired) {
            console.log('OTP is valid and not expired. Proceeding with login.');
            const [userRows] = await pool.query('SELECT * FROM users_apar WHERE email = ?', [email]);
            const userExists = userRows.length > 0;

            // if (!userExists) {
            //     console.log('User does not exist. Creating new user.');
            //     await pool.query('INSERT INTO users_apar (email, role) VALUES (?, ?)', [email, null]);
            // }
            if (!userExists && email.endsWith('@anaxee.com')) {
                console.log('User does not exist. Creating new user with role user3.');
                await pool.query('INSERT INTO users_apar (email, role) VALUES (?, ?)', [email, 'user3']);
            } else if (!userExists) {
                console.log('User does not exist. Creating new user with no role.');
                await pool.query('INSERT INTO users_apar (email, role) VALUES (?, ?)', [email, null]);
            }

            // Fetch user role
            const [roleRows] = await pool.query('SELECT role FROM users_apar WHERE email = ?', [email]);
            const userRole = roleRows[0].role;

            // Delete the used OTP
            await pool.query('DELETE FROM otp WHERE id = ?', [latestOtp.id]);

            // Generate JWT with user role
            const token = jwt.sign({ email: email, role: userRole }, JWT_SECRET, { expiresIn: '24h' });

            console.log('Sending successful login response with token');
            return res.status(200).json({ message: 'Login successful!', token: token, role: userRole });
        } else {
            console.log('OTP is invalid or expired. Sending error response.');
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }
    } catch (err) {
        console.error('Error in /verify-otp:', err);
        return res.status(500).json({ message: 'Error verifying OTP.', error: err.message });
    }
});

// Create a new dashboard (admin only)
app.post('/dashboards', authenticateJWT, async (req, res) => {
    const { title, url, allowedRoles } = req.body;
    const userRole = req.user.role;

    console.log('User attempting to create dashboard:', req.user);
    console.log('Request body:', req.body);

    if (userRole !== 'admin') {
        console.log(`Access denied. User role is ${userRole}, not admin.`);
        return res.status(403).json({ message: 'Access denied. Admin role required.' });
    }

    try {
        const [result] = await pool.query(
            'INSERT INTO dashboards (title, url, allowed_roles) VALUES (?, ?, ?)',
            [title, url, JSON.stringify(allowedRoles)]
        );
        console.log('Dashboard created successfully:', result);
        res.status(201).json({ id: result.insertId, title, url, allowedRoles });
    } catch (error) {
        console.error('Error creating dashboard:', error);
        res.status(500).json({ message: 'Error creating dashboard', error: error.message });
    }
});

// Get all dashboards (filtered by user role)
app.get('/dashboards', authenticateJWT, async (req, res) => {
    const userRole = req.user.role;

    try {
        let query = 'SELECT * FROM dashboards';
        let params = [];

        // Allow user3 to see all dashboards like admin
        if (userRole !== 'admin' && userRole !== 'user3') {
            query += ' WHERE JSON_CONTAINS(allowed_roles, ?)';
            params.push(JSON.stringify(userRole));
        }

        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching dashboards:', error);
        res.status(500).json({ message: 'Error fetching dashboards' });
    }
});

// Update a dashboard (admin only)
app.put('/dashboards/:id', authenticateJWT, async (req, res) => {
    const { id } = req.params;
    const { title, url, allowedRoles } = req.body;
    const userRole = req.user.role;

    // Allow only admin to update dashboards
    if (userRole !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }

    try {
        await pool.query(
            'UPDATE dashboards SET title = ?, url = ?, allowed_roles = ? WHERE id = ?',
            [title, url, JSON.stringify(allowedRoles), id]
        );
        res.json({ id, title, url, allowedRoles });
    } catch (error) {
        console.error('Error updating dashboard:', error);
        res.status(500).json({ message: 'Error updating dashboard' });
    }
});

// Delete a dashboard (admin only)
app.delete('/dashboards/:id', authenticateJWT, async (req, res) => {
    const { id } = req.params;
    const userRole = req.user.role;

    // Allow only admin to delete dashboards
    if (userRole !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }

    try {
        await pool.query('DELETE FROM dashboards WHERE id = ?', [id]);
        res.json({ message: 'Dashboard deleted successfully' });
    } catch (error) {
        console.error('Error deleting dashboard:', error);
        res.status(500).json({ message: 'Error deleting dashboard' });
    }
});

// Verify token endpoint
app.post('/verify-token', (req, res) => {
    const token = req.body.token;
    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token' });
        }
        res.json({ valid: true, email: decoded.email, role: decoded.role });
    });
});

// Add a new endpoint to check user role
app.get('/check-role', authenticateJWT, (req, res) => {
    console.log('User role check:', req.user);
    res.json({ role: req.user.role });
});

// Add this new endpoint for logout
app.post('/logout', authenticateJWT, (req, res) => {
    // In a more complex system, you might want to invalidate the token here
    // For now, we'll just send a success response
    res.json({ message: 'Logout successful' });
});

// Start the server
app.listen(5000, () => {
    console.log("Server is running on http://localhost:5000");
});
