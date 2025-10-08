const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'your-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Database setup
const db = new sqlite3.Database('./crm.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to SQLite database.');
        initializeDatabase();
    }
});

function initializeDatabase() {
    // Drop and recreate tables to ensure clean setup
    db.serialize(() => {
        // Drop existing tables
        db.run(`DROP TABLE IF EXISTS clients`);
        db.run(`DROP TABLE IF EXISTS users`);
        
        // Create users table
        db.run(`CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'agent',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

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
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (assigned_to) REFERENCES users (id),
            FOREIGN KEY (created_by) REFERENCES users (id)
        )`);

        // Create default admin user
        const defaultPassword = bcrypt.hashSync('admin123', 10);
        db.run(`INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)`, 
            ['admin', 'admin@crm.com', defaultPassword, 'admin'], function(err) {
                if (err) {
                    console.log('Admin user already exists or error:', err.message);
                } else {
                    console.log('✅ Default admin user created: admin / admin123');
                }
            });
    });
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

// AUTH ROUTES
// Register new user
app.post('/api/register', async (req, res) => {
    const { username, email, password, role = 'agent' } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
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

// Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    db.get(`SELECT * FROM users WHERE username = ? OR email = ?`, [username, username], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
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
// Get all clients (now filtered by user role)
app.get('/api/clients', requireAuth, (req, res) => {
    let query = `SELECT c.*, u.username as assigned_agent 
                 FROM clients c 
                 LEFT JOIN users u ON c.assigned_to = u.id`;
    
    // Agents can only see their assigned clients
    if (req.session.userRole === 'agent') {
        query += ` WHERE c.assigned_to = ?`;
        db.all(query, [req.session.userId], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
    } else {
        // Admins can see all clients
        db.all(query, [], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
    }
});

// Create client
app.post('/api/clients', requireAuth, (req, res) => {
    const { name, email, phone, status, notes, assigned_to } = req.body;
    
    const query = `INSERT INTO clients (name, email, phone, status, notes, assigned_to, created_by) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)`;
    
    // If no assigned_to specified, assign to current user
    const assignedTo = assigned_to || req.session.userId;
    
    db.run(query, [name, email, phone, status || 'Lead', notes || '', assignedTo, req.session.userId], 
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            
            res.json({
                id: this.lastID,
                name, email, phone,
                status: status || 'Lead',
                notes: notes || '',
                assigned_to: assignedTo,
                created_by: req.session.userId
            });
        }
    );
});

// Update client
app.put('/api/clients/:id', requireAuth, (req, res) => {
    const { id } = req.params;
    const { name, email, phone, status, notes, assigned_to } = req.body;
    
    const query = `UPDATE clients SET name = ?, email = ?, phone = ?, status = ?, notes = ?, assigned_to = ? WHERE id = ?`;
    
    db.run(query, [name, email, phone, status, notes, assigned_to, id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Client updated successfully' });
    });
});

// Delete client
app.delete('/api/clients/:id', requireAuth, (req, res) => {
    const { id } = req.params;
    
    const query = `DELETE FROM clients WHERE id = ?`;
    
    db.run(query, [id], function(err) {
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

// Serve the frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server - SIMPLE VERSION (NO ERRORS)
app.listen(PORT, () => {
    console.log(`🚀 Professional CRM running on port ${PORT}`);
    console.log(`📊 Default admin login: admin / admin123`);
});
