require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Initialize Firebase Admin SDK
let firebaseConfig;
try {
    firebaseConfig = JSON.parse(process.env.FIREBASE_CONFIG);
    admin.initializeApp({
        credential: admin.credential.cert(firebaseConfig)
    });
    console.log('🔥 Firebase initialized successfully');
} catch (error) {
    console.error('❌ Firebase initialization failed:', error.message);
    process.exit(1);
}

const db = admin.firestore();
const COLLECTION_NAME = 'quiz_attempts';

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('❌ JWT_SECRET is not defined in .env');
    process.exit(1);
}

// Hash admin password if it's not already hashed
let hashedAdminPassword = null;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    console.error('❌ ADMIN_USERNAME and ADMIN_PASSWORD must be defined in .env');
    process.exit(1);
}

// Hash password for comparison
async function hashAdminPassword() {
    try {
        // Check if password already hashed (starts with $2b$ or $2a$)
        if (ADMIN_PASSWORD.startsWith('$2b$') || ADMIN_PASSWORD.startsWith('$2a$')) {
            hashedAdminPassword = ADMIN_PASSWORD;
        } else {
            hashedAdminPassword = await bcrypt.hash(ADMIN_PASSWORD, 10);
            console.log('✅ Admin password hashed successfully');
        }
    } catch (error) {
        console.error('❌ Error hashing admin password:', error.message);
        process.exit(1);
    }
}

hashAdminPassword();

// JWT Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired. Please login again.' });
        }
        return res.status(403).json({ error: 'Invalid token.' });
    }
}

// API Routes

// POST /api/submit - Save quiz attempt
app.post('/api/submit', async (req, res) => {
    try {
        const { name, age, answer, isCorrect, timeTaken, timestamp } = req.body;

        // Validate required fields
        if (!name || !age || answer === undefined || isCorrect === undefined || timeTaken === undefined) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Validate data types
        if (typeof name !== 'string' || name.trim().length === 0) {
            return res.status(400).json({ error: 'Invalid name' });
        }
        if (typeof age !== 'number' || age < 1 || age > 120) {
            return res.status(400).json({ error: 'Invalid age' });
        }
        if (typeof timeTaken !== 'number' || timeTaken < 0) {
            return res.status(400).json({ error: 'Invalid time taken' });
        }

        // Prepare data for Firestore
        const data = {
            name: name.trim(),
            age: age,
            answer: answer.trim() || 'N/A',
            isCorrect: Boolean(isCorrect),
            timeTaken: timeTaken,
            timestamp: timestamp || new Date().toISOString(),
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };

        // Save to Firestore
        const docRef = await db.collection(COLLECTION_NAME).add(data);
        
        res.status(201).json({
            success: true,
            id: docRef.id,
            message: 'Data saved successfully'
        });

    } catch (error) {
        console.error('❌ Error saving data:', error);
        res.status(500).json({ error: 'Failed to save data' });
    }
});

// POST /api/login - Admin login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validate credentials presence
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        // Check username
        if (username !== ADMIN_USERNAME) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check password (using bcrypt if hashed, else direct comparison)
        let isPasswordValid = false;
        if (hashedAdminPassword) {
            isPasswordValid = await bcrypt.compare(password, hashedAdminPassword);
        } else {
            isPasswordValid = password === ADMIN_PASSWORD;
        }

        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { 
                username: username,
                role: 'admin'
            },
            JWT_SECRET,
            { 
                expiresIn: '24h' 
            }
        );

        res.json({
            success: true,
            token: token,
            message: 'Login successful'
        });

    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/dashboard - Get all quiz attempts (protected)
app.get('/api/dashboard', authenticateToken, async (req, res) => {
    try {
        const snapshot = await db.collection(COLLECTION_NAME)
            .orderBy('timestamp', 'desc')
            .get();

        const data = [];
        snapshot.forEach(doc => {
            const docData = doc.data();
            data.push({
                id: doc.id,
                name: docData.name || 'N/A',
                age: docData.age || 'N/A',
                answer: docData.answer || 'N/A',
                isCorrect: docData.isCorrect !== undefined ? docData.isCorrect : false,
                timeTaken: docData.timeTaken || 0,
                timestamp: docData.timestamp || new Date().toISOString()
            });
        });

        res.json(data);

    } catch (error) {
        console.error('❌ Error fetching dashboard data:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard data' });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Serve index.html for root route
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('❌ Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(port, () => {
    console.log(`✅ Server running on port ${port}`);
    console.log(`📊 Dashboard: http://localhost:${port}/dashboard.html`);
    console.log(`🔐 Login: http://localhost:${port}/login.html`);
    console.log(`📝 Quiz: http://localhost:${port}/`);
});

module.exports = app;
