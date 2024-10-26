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

// Modified authenticateJWT middleware to handle multiple roles
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
                        name: "User",
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
                    authkey: "103801ASIjpSVep5dadb6b2",
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



// Modified verify-otp endpoint to handle multiple roles
app.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;

    try {
        const [rows] = await pool.query(
            'SELECT * FROM otp WHERE email = ? ORDER BY created_at DESC LIMIT 1',
            [email]
        );
        const latestOtp = rows[0];

        if (!latestOtp) {
            console.log('No OTP found for this email');
            return res.status(400).json({ message: 'No OTP found for this email.' });
        }

        const isOtpValid = latestOtp.otp === otp;
        const isOtpExpired = new Date() >= new Date(latestOtp.expires_at);

        if (isOtpValid && !isOtpExpired) {
            // Check if user exists and get their roles
            const [userRows] = await pool.query(
                'SELECT * FROM users_apar WHERE email = ?',
                [email]
            );

            let userRoles;
            if (userRows.length === 0) {
                // Create new user with empty roles array
                await pool.query(
                    'INSERT INTO users_apar (email, roles) VALUES (?, ?)',
                    [email, JSON.stringify([])]
                );
                userRoles = [];
            } else {
                // Log the roles fetched from the database
                console.log('Fetched roles from DB:', userRows[0].roles);
                
                // Check if roles are already an array
                if (Array.isArray(userRows[0].roles)) {
                    userRoles = userRows[0].roles; // Use directly if it's an array
                } else {
                    // If it's a string, parse it as JSON
                    userRoles = JSON.parse(userRows[0].roles);
                }
            }

            // Delete the used OTP
            await pool.query('DELETE FROM otp WHERE id = ?', [latestOtp.id]);

            // Generate JWT with user roles array
            const token = jwt.sign(
                { email: email, roles: userRoles },
                JWT_SECRET,
                { expiresIn: '1h' }
            );

            return res.status(200).json({
                message: 'Login successful!',
                token: token,
                roles: userRoles
            });
        } else {
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }
    } catch (err) {
        console.error('Error in /verify-otp:', err);
        return res.status(500).json({ message: 'Error verifying OTP.', error: err.message });
    }
});

// Modified dashboard endpoints to handle multiple roles
app.post('/dashboards', authenticateJWT, async (req, res) => {
    const { title, url, allowedRoles } = req.body;
    const userRoles = req.user.roles;

    // Check if user has admin role
    if (!userRoles.includes('admin')) {
        return res.status(403).json({ message: 'Access denied. Admin role required.' });
    }

    try {
        const [result] = await pool.query(
            'INSERT INTO dashboards (title, url, allowed_roles) VALUES (?, ?, ?)',
            [title, url, JSON.stringify(allowedRoles)]
        );
        console.log('dashboard created:', error)
        res.status(201).json({ id: result.insertId, title, url, allowedRoles });
    } catch (error) {
        console.error('Error creating dashboard:', error);
        res.status(500).json({ message: 'Error creating dashboard', error: error.message });
    }
});

// Get dashboards accessible to user based on their roles
app.get('/dashboards', authenticateJWT, async (req, res) => {
    const userRoles = req.user.roles;

    try {
        let query = 'SELECT * FROM dashboards';
        let params = [];

        if (!userRoles.includes('admin')) {
            // Check if any of user's roles match with allowed_roles
            const roleChecks = userRoles.map(role => 
                `JSON_CONTAINS(allowed_roles, JSON_QUOTE('${role}'))`
            ).join(' OR ');
            
            query += ` WHERE ${roleChecks}`;
        }

        const [rows] = await pool.query(query);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching dashboards:', error);
        res.status(500).json({ message: 'Error fetching dashboards' });
    }
});

app.put('/dashboards/:id', authenticateJWT, async (req, res) => {
    const { id } = req.params;
    const { title, url, allowedRoles } = req.body;
    const userRoles = req.user.roles;

    // Check if user has admin role
    if (!userRoles.includes('admin')) {
        return res.status(403).json({ message: 'Access denied. Admin role required.' });
    }

    try {
        await pool.query(
            'UPDATE dashboards SET title = ?, url = ?, allowed_roles = ? WHERE id = ?',
            [title, url, JSON.stringify(allowedRoles), id]
        );
        res.status(200).json({ message: 'Dashboard updated successfully' });
    } catch (error) {
        console.error('Error updating dashboard:', error);
        res.status(500).json({ message: 'Error updating dashboard', error: error.message });
    }
});

app.delete('/dashboards/:id', authenticateJWT, async (req, res) => {
    const { id } = req.params;
    const userRoles = req.user.roles;

    // Check if user has admin role
    if (!userRoles.includes('admin')) {
        return res.status(403).json({ message: 'Access denied. Admin role required.' });
    }

    try {
        await pool.query('DELETE FROM dashboards WHERE id = ?', [id]);
        res.status(200).json({ message: 'Dashboard deleted successfully' });
    } catch (error) {
        console.error('Error deleting dashboard:', error);
        res.status(500).json({ message: 'Error deleting dashboard', error: error.message });
    }
});


app.listen(5000, () => {
    console.log("Server is running on http://localhost:5000");
});
