require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'DELETE', 'PUT', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
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
const SETTINGS_COLLECTION = 'quiz_settings';
const LOGS_COLLECTION = 'quiz_logs';
const USERS_COLLECTION = 'quiz_users';

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('❌ JWT_SECRET is not defined in .env');
    process.exit(1);
}

// Hash admin password
let hashedAdminPassword = null;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    console.error('❌ ADMIN_USERNAME and ADMIN_PASSWORD must be defined in .env');
    process.exit(1);
}

async function hashAdminPassword() {
    try {
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

// Helper function to get client IP
function getClientIP(req) {
    return req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress || req.ip;
}

// Helper function to log actions
async function logAction(action, details) {
    try {
        await db.collection(LOGS_COLLECTION).add({
            action: action,
            details: details,
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            createdAt: new Date().toISOString()
        });
    } catch (error) {
        console.error('❌ Error logging action:', error);
    }
}

// Helper function to validate quiz data
function validateQuizData(data) {
    const errors = [];
    
    if (!data.name || typeof data.name !== 'string' || data.name.trim().length === 0) {
        errors.push('Name is required and must be a non-empty string');
    }
    
    if (!data.age || typeof data.age !== 'number' || data.age < 1 || data.age > 120) {
        errors.push('Age must be a number between 1 and 120');
    }
    
    if (data.answer === undefined || data.answer === null) {
        errors.push('Answer is required');
    }
    
    if (typeof data.isCorrect !== 'boolean') {
        errors.push('isCorrect must be a boolean');
    }
    
    if (typeof data.timeTaken !== 'number' || data.timeTaken < 0) {
        errors.push('timeTaken must be a non-negative number');
    }
    
    return errors;
}

// POST /api/submit - Save quiz attempt
app.post('/api/submit', async (req, res) => {
    try {
        console.log('📥 Received submission:', req.body);
        
        // Check if quiz is open
        const settingsDoc = await db.collection(SETTINGS_COLLECTION).doc('quiz_settings').get();
        let isOpen = false;
        if (settingsDoc.exists) {
            isOpen = settingsDoc.data().isOpen === true;
        }
        
        if (!isOpen) {
            console.log('❌ Quiz is closed');
            return res.status(403).json({ error: 'Quiz is currently closed' });
        }

        const { name, age, answer, isCorrect, timeTaken, timestamp, ip } = req.body;

        console.log('📊 Data received:', { name, age, answer, isCorrect, timeTaken, ip });

        // Validate required fields
        if (!name || !age || answer === undefined || isCorrect === undefined || timeTaken === undefined) {
            console.log('❌ Missing fields:', { name, age, answer, isCorrect, timeTaken });
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Validate data
        const validationErrors = validateQuizData(req.body);
        if (validationErrors.length > 0) {
            console.log('❌ Validation errors:', validationErrors);
            return res.status(400).json({ error: validationErrors.join(', ') });
        }

        // Check if user already participated (by name, age, IP)
        const userIP = ip || 'unknown';
        const existingUser = await db.collection(USERS_COLLECTION)
            .where('name', '==', name.trim())
            .where('age', '==', age)
            .get();

        if (!existingUser.empty) {
            console.log('⚠️ User already participated:', { name, age });
            return res.status(403).json({ 
                error: 'You have already participated in this quiz. Multiple attempts are not allowed.' 
            });
        }

        // Prepare data for Firestore
        const data = {
            name: name.trim(),
            age: age,
            answer: answer.trim() || 'N/A',
            isCorrect: Boolean(isCorrect),
            timeTaken: timeTaken,
            ip: userIP,
            timestamp: timestamp || new Date().toISOString(),
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            status: 'completed',
            isOpen: true
        };

        console.log('💾 Saving data to Firestore:', data);

        // Save user to users collection (to prevent re-entry)
        const userRef = await db.collection(USERS_COLLECTION).add({
            name: name.trim(),
            age: age,
            ip: userIP,
            attemptId: null,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        // Save to Firestore
        const docRef = await db.collection(COLLECTION_NAME).add(data);
        
        // Update user with attempt ID
        await userRef.update({ attemptId: docRef.id });

        // Log action
        await logAction('quiz_attempt', {
            name: name.trim(),
            age: age,
            isCorrect: Boolean(isCorrect),
            attemptId: docRef.id,
            ip: userIP
        });

        console.log('✅ Data saved successfully! ID:', docRef.id);

        res.status(201).json({
            success: true,
            id: docRef.id,
            message: 'Data saved successfully'
        });

    } catch (error) {
        console.error('❌ Error saving data:', error);
        console.error('❌ Error stack:', error.stack);
        res.status(500).json({ 
            error: 'Failed to save data',
            details: error.message 
        });
    }
});

// POST /api/login - Admin login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        if (username !== ADMIN_USERNAME) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        let isPasswordValid = false;
        if (hashedAdminPassword) {
            isPasswordValid = await bcrypt.compare(password, hashedAdminPassword);
        } else {
            isPasswordValid = password === ADMIN_PASSWORD;
        }

        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

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

        await logAction('admin_login', { username: username });

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
                ip: docData.ip || 'unknown',
                timestamp: docData.timestamp || new Date().toISOString(),
                status: docData.status || 'completed',
                isOpen: docData.isOpen !== undefined ? docData.isOpen : true
            });
        });

        res.json(data);

    } catch (error) {
        console.error('❌ Error fetching dashboard data:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard data' });
    }
});

// DELETE /api/delete/:id - Delete specific quiz attempt (protected)
app.delete('/api/delete/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        const attemptDoc = await db.collection(COLLECTION_NAME).doc(id).get();
        if (!attemptDoc.exists) {
            return res.status(404).json({ error: 'Attempt not found' });
        }
        
        const attemptData = attemptDoc.data();
        
        await db.collection(COLLECTION_NAME).doc(id).delete();
        
        const userQuery = await db.collection(USERS_COLLECTION)
            .where('attemptId', '==', id)
            .get();
        
        if (!userQuery.empty) {
            userQuery.forEach(async (doc) => {
                await doc.ref.delete();
            });
        }

        await logAction('delete_attempt', {
            attemptId: id,
            name: attemptData.name,
            age: attemptData.age,
            ip: attemptData.ip
        });

        res.json({ success: true, message: 'Attempt deleted successfully' });

    } catch (error) {
        console.error('❌ Error deleting attempt:', error);
        res.status(500).json({ error: 'Failed to delete attempt' });
    }
});

// DELETE /api/delete-all - Delete all quiz attempts (protected)
app.delete('/api/delete-all', authenticateToken, async (req, res) => {
    try {
        const snapshot = await db.collection(COLLECTION_NAME).get();
        const batch = db.batch();
        
        snapshot.forEach(doc => {
            batch.delete(doc.ref);
        });

        await batch.commit();

        const usersSnapshot = await db.collection(USERS_COLLECTION).get();
        const usersBatch = db.batch();
        usersSnapshot.forEach(doc => {
            usersBatch.delete(doc.ref);
        });
        await usersBatch.commit();

        await logAction('delete_all', { count: snapshot.size });

        res.json({ success: true, message: 'All data deleted successfully' });

    } catch (error) {
        console.error('❌ Error deleting data:', error);
        res.status(500).json({ error: 'Failed to delete data' });
    }
});

// POST /api/toggle-user/:id - Toggle specific user's quiz status (protected)
app.post('/api/toggle-user/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { isOpen } = req.body;
        
        if (typeof isOpen !== 'boolean') {
            return res.status(400).json({ error: 'isOpen must be a boolean' });
        }

        const userDoc = await db.collection(COLLECTION_NAME).doc(id).get();
        if (!userDoc.exists) {
            return res.status(404).json({ error: 'Attempt not found' });
        }

        const userData = userDoc.data();

        await db.collection(COLLECTION_NAME).doc(id).update({
            isOpen: isOpen,
            status: isOpen ? 'open' : 'closed',
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        await logAction('toggle_user', {
            attemptId: id,
            name: userData.name,
            isOpen: isOpen
        });

        res.json({ 
            success: true, 
            isOpen: isOpen,
            message: `User ${userData.name} ${isOpen ? 'opened' : 'closed'} successfully`
        });

    } catch (error) {
        console.error('❌ Error toggling user status:', error);
        res.status(500).json({ error: 'Failed to toggle user status' });
    }
});

// GET /api/quiz-status - Get quiz open/closed status (protected)
app.get('/api/quiz-status', authenticateToken, async (req, res) => {
    try {
        const settingsDoc = await db.collection(SETTINGS_COLLECTION).doc('quiz_settings').get();
        let isOpen = false;
        if (settingsDoc.exists) {
            isOpen = settingsDoc.data().isOpen === true;
        }
        res.json({ isOpen });
    } catch (error) {
        console.error('❌ Error fetching quiz status:', error);
        res.status(500).json({ error: 'Failed to fetch quiz status' });
    }
});

// POST /api/toggle-quiz - Toggle quiz open/closed (protected)
app.post('/api/toggle-quiz', authenticateToken, async (req, res) => {
    try {
        const { isOpen } = req.body;
        if (typeof isOpen !== 'boolean') {
            return res.status(400).json({ error: 'isOpen must be a boolean' });
        }

        await db.collection(SETTINGS_COLLECTION).doc('quiz_settings').set({
            isOpen: isOpen,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        await logAction('toggle_quiz_global', { isOpen: isOpen });

        res.json({ success: true, isOpen });
    } catch (error) {
        console.error('❌ Error toggling quiz status:', error);
        res.status(500).json({ error: 'Failed to toggle quiz status' });
    }
});

// GET /api/logs - Get all logs (protected)
app.get('/api/logs', authenticateToken, async (req, res) => {
    try {
        const snapshot = await db.collection(LOGS_COLLECTION)
            .orderBy('timestamp', 'desc')
            .limit(100)
            .get();

        const logs = [];
        snapshot.forEach(doc => {
            logs.push({
                id: doc.id,
                ...doc.data()
            });
        });

        res.json(logs);
    } catch (error) {
        console.error('❌ Error fetching logs:', error);
        res.status(500).json({ error: 'Failed to fetch logs' });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Serve login page
app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/public/login.html');
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

// مسار اختبار للكتابة في Firestore
app.get('/api/test-firebase', async (req, res) => {
    try {
        const testDoc = await db.collection('test_collection').add({
            message: 'Test connection from Vercel',
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });
        res.json({ success: true, id: testDoc.id, message: 'Firestore write successful!' });
    } catch (error) {
        console.error('❌ Firestore write test failed:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Start server
app.listen(port, () => {
    console.log(`✅ Server running on port ${port}`);
    console.log(`📊 Dashboard: http://localhost:${port}/dashboard.html`);
    console.log(`🔐 Login: http://localhost:${port}/login`);
    console.log(`📝 Quiz: http://localhost:${port}/`);
});

module.exports = app;
