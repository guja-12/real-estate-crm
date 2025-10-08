const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const app = express();
const PORT = process.env.PORT || 3000;

// Enhanced CORS configuration
app.use(cors({
    origin: ['https://my-crm-89g2.onrender.com', 'http://localhost:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.options('*', cors());
app.use(express.json());
app.use(express.static('.'));

// Enhanced session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'prime-crm-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'lax'
    }
}));

// Database setup - Using file database for persistence
const db = new sqlite3.Database('./crm.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to SQLite database.');
        initializeDatabase();
    }
});

function initializeDatabase() {
    // Create users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'agent',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Create clients table
    db.run(`CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT,
        status TEXT DEFAULT 'Lead',
        notes TEXT,
        assigned_to INTEGER,
        created_by INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Create default admin user - SECURE: Only one way to login
    const defaultPassword = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT OR IGNORE INTO users (username, email, password, role) VALUES (?, ?, ?, ?)`, 
        ['admin', 'admin@crm.com', defaultPassword, 'admin'], function(err) {
            if (err) {
                console.log('Error creating admin user:', err.message);
            } else {
                console.log('✅ SECURE: Default admin user created: admin / admin123');
                console.log('🔒 NO DEMO MODE - Only valid users can login');
            }
        });

    // Add demo clients (these are just initial data, not demo mode)
    db.run(`INSERT OR IGNORE INTO clients (name, email, phone, status, notes, assigned_to, created_by) VALUES 
        ('John Smith', 'john@example.com', '(555) 123-4567', 'Lead', 'Interested in downtown condo', 1, 1),
        ('Sarah Johnson', 'sarah@example.com', '(555) 987-6543', 'Contacted', 'Looking for family home', 1, 1),
        ('Mike Wilson', 'mike@example.com', '(555) 456-7890', 'Negotiation', 'Commercial property inquiry', 1, 1)
    `);
}

// Authentication middleware
const requireAuth = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Authentication required' });
    }
};

// Routes

// Serve the main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'CRM API is running', secure: true });
});

// AUTH ROUTES - STRICT AUTHENTICATION
// Register new user
app.post('/api/register', async (req, res) => {
    const { username, email, password, role = 'agent' } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    // Validate password strength
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run(`INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)`,
            [username, email, hashedPassword, role],
            function(err) {
                if (err) {
                    return res.status(400).json({ error: 'Username or email already exists' });
                }
                res.json({ 
                    message: 'User created successfully',
                    user: { id: this.lastID, username, email, role }
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Login - STRICT AUTHENTICATION - NO DEMO MODE
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    db.get(`SELECT * FROM users WHERE username = ? OR email = ?`, [username, username], async (err, user) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        try {
            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(401).json({ error: 'Invalid username or password' });
            }

            // Create session
            req.session.userId = user.id;
            req.session.userRole = user.role;

            res.json({
                message: 'Login successful',
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role
                }
            });
        } catch (error) {
            console.error('Password comparison error:', error);
            return res.status(500).json({ error: 'Authentication error' });
        }
    });
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.json({ message: 'Logout successful' });
    });
});

// Get current user
app.get('/api/user', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    db.get(`SELECT id, username, email, role FROM users WHERE id = ?`, [req.session.userId], (err, user) => {
        if (err || !user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ user });
    });
});

// CLIENT ROUTES (Protected)
app.get('/api/clients', requireAuth, (req, res) => {
    let query = `SELECT c.*, u.username as assigned_agent 
                 FROM clients c 
                 LEFT JOIN users u ON c.assigned_to = u.id`;
    
    if (req.session.userRole === 'agent') {
        query += ` WHERE c.assigned_to = ?`;
        db.all(query, [req.session.userId], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
    } else {
        db.all(query, [], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
    }
});

app.post('/api/clients', requireAuth, (req, res) => {
    const { name, email, phone, status, notes, assigned_to } = req.body;
    
    if (!name || !email) {
        return res.status(400).json({ error: 'Name and email are required' });
    }

    const query = `INSERT INTO clients (name, email, phone, status, notes, assigned_to, created_by) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)`;
    
    const assignedTo = assigned_to || req.session.userId;
    
    db.run(query, [name, email, phone, status || 'Lead', notes || '', assignedTo, req.session.userId], 
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            
            db.get(`SELECT c.*, u.username as assigned_agent 
                    FROM clients c 
                    LEFT JOIN users u ON c.assigned_to = u.id 
                    WHERE c.id = ?`, [this.lastID], (err, row) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json(row);
            });
        }
    );
});

app.put('/api/clients/:id', requireAuth, (req, res) => {
    const { id } = req.params;
    const { name, email, phone, status, notes, assigned_to } = req.body;
    
    if (!name || !email) {
        return res.status(400).json({ error: 'Name and email are required' });
    }

    const query = `UPDATE clients SET name = ?, email = ?, phone = ?, status = ?, notes = ?, assigned_to = ? WHERE id = ?`;
    
    db.run(query, [name, email, phone, status, notes, assigned_to, id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Client updated successfully' });
    });
});

app.delete('/api/clients/:id', requireAuth, (req, res) => {
    const { id } = req.params;
    
    db.run(`DELETE FROM clients WHERE id = ?`, [id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Client deleted successfully' });
    });
});

// USER MANAGEMENT ROUTES (Admin only)
app.get('/api/users', requireAuth, (req, res) => {
    if (req.session.userRole !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    
    db.all(`SELECT id, username, email, role, created_at FROM users`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 SECURE CRM running on port ${PORT}`);
    console.log(`📊 Default admin login: admin / admin123`);
    console.log(`🔒 STRICT AUTHENTICATION ENABLED - NO DEMO MODE`);
    console.log(`❌ Invalid credentials will be REJECTED`);
});
