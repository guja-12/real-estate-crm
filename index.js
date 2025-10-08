const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
const PORT = process.env.PORT || 3000;

// Enhanced CORS configuration for cross-device access
app.use(cors({
    origin: ['https://my-crm-89g2.onrender.com', 'http://localhost:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.options('*', cors());
app.use(express.json());

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, 'public')));

// JWT Secret Key
const JWT_SECRET = process.env.JWT_SECRET || 'prime-crm-jwt-secret-key-change-in-production';

// Database setup - Use in-memory database for Render compatibility
const db = new sqlite3.Database(':memory:', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to SQLite in-memory database.');
        initializeDatabase();
    }
});

function initializeDatabase() {
    console.log('Initializing database tables...');
    
    // Create users table
    db.run(`CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'agent',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) {
            console.error('Error creating users table:', err.message);
        } else {
            console.log('✅ Users table created');
            createDefaultUsers();
        }
    });

    // Create clients table
    db.run(`CREATE TABLE clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT,
        status TEXT DEFAULT 'Lead',
        notes TEXT,
        assigned_to INTEGER,
        created_by INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) {
            console.error('Error creating clients table:', err.message);
        } else {
            console.log('✅ Clients table created');
            createDemoClients();
        }
    });
}

function createDefaultUsers() {
    const defaultPassword = bcrypt.hashSync('admin123', 10);
    
    db.run(`INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)`, 
        ['admin', 'admin@crm.com', defaultPassword, 'admin'], function(err) {
            if (err) {
                console.log('Admin user already exists or error:', err.message);
            } else {
                console.log('✅ Default admin user created: admin / admin123');
            }
        });

    // Create a demo agent user
    const agentPassword = bcrypt.hashSync('agent123', 10);
    db.run(`INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)`, 
        ['agent', 'agent@crm.com', agentPassword, 'agent'], function(err) {
            if (err) {
                console.log('Agent user already exists or error:', err.message);
            } else {
                console.log('✅ Demo agent user created: agent / agent123');
            }
        });
}

function createDemoClients() {
    db.run(`INSERT INTO clients (name, email, phone, status, notes, assigned_to, created_by) VALUES 
        ('John Smith', 'john@example.com', '(555) 123-4567', 'Lead', 'Interested in downtown condo', 1, 1),
        ('Sarah Johnson', 'sarah@example.com', '(555) 987-6543', 'Contacted', 'Looking for family home', 1, 1),
        ('Mike Wilson', 'mike@example.com', '(555) 456-7890', 'Negotiation', 'Commercial property inquiry', 1, 1),
        ('Emily Davis', 'emily@example.com', '(555) 111-2222', 'Closed', 'Purchased luxury apartment', 2, 1),
        ('Robert Brown', 'robert@example.com', '(555) 333-4444', 'Contacted', 'First-time home buyer', 2, 1)
    `, function(err) {
        if (err) {
            console.log('Demo clients already exist or error:', err.message);
        } else {
            console.log('✅ Demo clients created');
        }
    });
}

// JWT Authentication middleware
const requireAuth = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token.' });
    }
};

// Routes

// Serve the main page from public folder
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Health check with database status
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'CRM API is running', 
        secure: true,
        authentication: 'JWT-based',
        crossDevice: 'Enabled'
    });
});

// AUTH ROUTES - JWT AUTHENTICATION
app.post('/api/register', async (req, res) => {
    const { username, email, password, role = 'agent' } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

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
                
                // Generate JWT token for new user
                const token = jwt.sign(
                    { id: this.lastID, username, email, role },
                    JWT_SECRET,
                    { expiresIn: '24h' }
                );
                
                res.json({ 
                    message: 'User created successfully',
                    user: { id: this.lastID, username, email, role },
                    token
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Login - JWT AUTHENTICATION
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

            // Generate JWT token
            const token = jwt.sign(
                { 
                    id: user.id, 
                    username: user.username, 
                    email: user.email, 
                    role: user.role 
                },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.json({
                message: 'Login successful',
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role
                },
                token // Send token to client
            });
        } catch (error) {
            console.error('Password comparison error:', error);
            return res.status(500).json({ error: 'Authentication error' });
        }
    });
});

// Logout - Client-side token removal
app.post('/api/logout', (req, res) => {
    res.json({ message: 'Logout successful' });
});

// Get current user from token
app.get('/api/user', requireAuth, (req, res) => {
    db.get(`SELECT id, username, email, role FROM users WHERE id = ?`, [req.user.id], (err, user) => {
        if (err || !user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ user });
    });
});

// CLIENT ROUTES
app.get('/api/clients', requireAuth, (req, res) => {
    let query = `SELECT c.*, u.username as assigned_agent 
                 FROM clients c 
                 LEFT JOIN users u ON c.assigned_to = u.id`;
    
    if (req.user.role === 'agent') {
        query += ` WHERE c.assigned_to = ?`;
        db.all(query, [req.user.id], (err, rows) => {
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
    
    const assignedTo = assigned_to || req.user.id;
    
    db.run(query, [name, email, phone, status || 'Lead', notes || '', assignedTo, req.user.id], 
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

// USER MANAGEMENT ROUTES
app.get('/api/users', requireAuth, (req, res) => {
    if (req.user.role !== 'admin') {
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
    console.log(`📁 Serving files from: ${path.join(__dirname, 'public')}`);
    console.log(`🔐 Authentication: JWT-based (works across all devices)`);
    console.log(`📊 Available logins:`);
    console.log(`   👑 Admin: admin / admin123`);
    console.log(`   👥 Agent: agent / agent123`);
    console.log(`🔒 STRICT AUTHENTICATION ENABLED - NO DEMO MODE`);
    console.log(`❌ Invalid credentials will be REJECTED`);
    console.log(`💾 Database: In-memory SQLite (resets on server restart)`);
});
