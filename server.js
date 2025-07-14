const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3002;

// Security Keys & Configs
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32);
const IV_LENGTH = 16;
const SALT_LENGTH = 64;
const TAG_LENGTH = 16;
const ALGORITHM = 'aes-256-gcm';

// Rate Limiters
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests, please try again later' }
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many login attempts, please try again later' }
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 giờ
    max: 3, // 3 lần/giờ/IP
    message: { error: 'Too many registration attempts, please try again later' }
});

// Security Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: "same-site" },
    dnsPrefetchControl: { allow: false },
    frameguard: { action: "deny" },
    hidePoweredBy: true,
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    ieNoOpen: true,
    noSniff: true,
    permittedCrossDomainPolicies: { permittedPolicies: "none" },
    referrerPolicy: { policy: "same-origin" },
    xssFilter: true,
}));

app.use(apiLimiter);
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
    maxAge: 86400
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.static('.', { dotfiles: 'deny' }));

// Encryption Utilities
function encrypt(text, userKey = ENCRYPTION_KEY) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = crypto.pbkdf2Sync(userKey, salt, 2145, 32, 'sha512');
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
}

function decrypt(data, userKey = ENCRYPTION_KEY) {
    try {
        const bData = Buffer.from(data, 'base64');
        const salt = bData.slice(0, SALT_LENGTH);
        const iv = bData.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
        const tag = bData.slice(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
        const text = bData.slice(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
        const key = crypto.pbkdf2Sync(userKey, salt, 2145, 32, 'sha512');
        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(tag);
        return decipher.update(text, 'binary', 'utf8') + decipher.final('utf8');
    } catch (error) {
        console.error('Decryption error:', error);
        throw new Error('Invalid encrypted data');
    }
}

function generateAccountId(accountLine) {
    return crypto.createHash('sha256')
        .update(accountLine + ENCRYPTION_KEY)
        .digest('hex')
        .substring(0, 16);
}

function generateUserToken(user) {
    const tokenData = {
        id: user.username,
        role: user.role,
        key: crypto.randomBytes(32).toString('hex')
    };
    
    return {
        token: jwt.sign(tokenData, JWT_SECRET, { expiresIn: '24h' }),
        encryptionKey: tokenData.key
    };
    }
    
// Authentication Middleware
function authenticateToken(req, res, next) {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'Authentication required' });
}

        jwt.verify(token, JWT_SECRET, (err, decoded) => {
            if (err) return res.status(403).json({ error: 'Invalid or expired token' });
            req.user = decoded;
            req.encryptionKey = decoded.key;
            next();
        });
    } catch (error) {
        console.error('Auth error:', error);
        res.status(500).json({ error: 'Authentication error' });
    }
}

function requireAdmin(req, res, next) {
    if (!req.user || req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        next();
}

// File paths
const USERS_FILE = path.join(__dirname, 'users.json');
const ORDERS_FILE = path.join(__dirname, 'orders.json');
const ACCOUNTS_FILE = path.join(__dirname, 'ACC.txt');
const HIDDEN_ACCOUNTS_FILE = path.join(__dirname, 'hidden_accounts.txt');

// Validation Rules
const validateRegistration = [
    body('username').trim().isLength({ min: 4 }).escape(),
    body('password').isLength({ min: 8 })
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
        .withMessage('Password must contain uppercase, lowercase, number and special character'),
    body('email').isEmail().normalizeEmail()
];

// Register endpoint
app.post('/api/register', registerLimiter, async (req, res) => {
    try {
        let data = req.body;
        if (data.payload) {
            try {
                data = JSON.parse(Buffer.from(data.payload, 'base64').toString('utf8'));
            } catch {
                return res.status(400).json({ error: 'Invalid payload encoding' });
            }
        }
        const { username, password, email } = data;

        // Validate username
        if (!username || typeof username !== 'string' || username.trim().length < 4) {
            return res.status(400).json({ error: 'Username must be at least 4 characters' });
        }
        // Validate email
        if (!email || !/^[^@]+@[^@]+\.[^@]+$/.test(email)) {
            return res.status(400).json({ error: 'Invalid email' });
        }
        // Validate password
        if (
            !password ||
            password.length < 8 ||
            !/[A-Z]/.test(password) ||
            !/[a-z]/.test(password) ||
            !/[0-9]/.test(password) ||
            !/[@$!%*?&]/.test(password)
        ) {
            return res.status(400).json({ error: 'Password must contain uppercase, lowercase, number and special character' });
        }

        const users = JSON.parse(await fs.promises.readFile(USERS_FILE, 'utf8') || '[]');
        if (users.find(u => u.username === username)) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = {
            username,
            password: hashedPassword,
            email: encrypt(email),
            role: 'user',
            balance: 0,
            createdAt: new Date().toISOString()
        };
        users.push(newUser);
        await fs.promises.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
        const { token, encryptionKey } = generateUserToken(newUser);
        res.json({
            success: true,
            user: {
                username: newUser.username,
                role: newUser.role,
                balance: newUser.balance
            },
            token,
            encryptionKey
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Login endpoint
app.post('/api/login', loginLimiter, async (req, res) => {
    try {
    const { username, password } = req.body;
        const users = JSON.parse(await fs.promises.readFile(USERS_FILE, 'utf8') || '[]');
        const user = users.find(u => u.username === username);
        
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const { token, encryptionKey } = generateUserToken(user);

        // Decrypt sensitive data for response
        let decryptedEmail = '';
        try {
            decryptedEmail = decrypt(user.email);
        } catch (e) {
            console.error('Decryption error (email):', e);
            decryptedEmail = user.email || '';
        }
        res.json({
            success: true,
            user: {
                username: user.username,
                email: decryptedEmail,
                role: user.role,
                balance: user.balance
            },
            token,
            encryptionKey
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Thông tin user hiện tại (theo token)
app.get('/api/users/me', authenticateToken, async (req, res) => {
    try {
        const users = JSON.parse(await fs.promises.readFile(USERS_FILE, 'utf8') || '[]');
        const user = users.find(u => u.username === req.user.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({
            username: user.username,
            role: user.role,
            balance: user.balance,
            createdAt: user.createdAt
        });
    } catch (error) {
        console.error('Error get user info:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Lấy lịch sử mua hàng của user hiện tại
app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        const data = await fs.promises.readFile(ORDERS_FILE, 'utf8');
        const orders = JSON.parse(data || '[]');
        // Lọc đơn hàng theo user hiện tại
        const userOrders = orders.filter(order => order.userId === req.user.id);
        res.json(userOrders);
    } catch (error) {
        console.error('Error reading user orders:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get accounts (public API but with encryption)
app.get('/api/accounts', authenticateToken, async (req, res) => {
    try {
        const data = await fs.promises.readFile(ACCOUNTS_FILE, 'utf8');
        const accounts = data.trim().split('\n').filter(line => line.trim());
        const accountIds = accounts.map(account => {
            const [username, points, websites] = account.split('|');
            const id = generateAccountId(account);
            const halfLength = Math.ceil((username || '').length / 2);
            const maskedUsername = (username || '').substring(0, halfLength) + '*'.repeat(halfLength);
            return {
                id,
                points: points || '0',
                username: maskedUsername,
                websites: websites || ''
            };
        });
        res.json({ 
            total: String(accounts.length),
            accounts: accountIds
        });
    } catch (error) {
        console.error('Error reading accounts:', error);
        res.status(500).json({ error: 'Server error' });
            }
        });
        
// Admin APIs with full encryption
app.get('/api/admin/accounts', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const data = await fs.promises.readFile(ACCOUNTS_FILE, 'utf8');
        res.json({ data: encrypt(data, req.encryptionKey) });
    } catch (error) {
        console.error('Error reading accounts for admin:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/admin/orders', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const data = await fs.promises.readFile(ORDERS_FILE, 'utf8');
        const orders = JSON.parse(data || '[]');
        
        const ordersWithAccounts = await Promise.all(orders.map(async order => {
            try {
                let accountData = await fs.promises.readFile(ACCOUNTS_FILE, 'utf8');
                let accounts = accountData.trim().split('\n');
                let account = accounts.find(acc => generateAccountId(acc) === order.accountId);
            
            if (!account) {
                    accountData = await fs.promises.readFile(HIDDEN_ACCOUNTS_FILE, 'utf8');
                    accounts = accountData.trim().split('\n');
                    account = accounts.find(acc => generateAccountId(acc) === order.accountId);
            }
            
                if (account) {
                    const parts = account.split('|');
                    return {
                        ...order,
                        accountUsername: encrypt(parts[2], req.encryptionKey),
                        accountPassword: encrypt(parts[3], req.encryptionKey),
                        accountDetails: encrypt(account, req.encryptionKey)
                    };
                }
                return order;
            } catch (error) {
                console.error('Error processing order:', error);
                return order;
            }
        }));
        
        res.json(encrypt(JSON.stringify(ordersWithAccounts), req.encryptionKey));
    } catch (error) {
        console.error('Error reading orders for admin:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Thêm vào server.js
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = JSON.parse(await fs.promises.readFile(USERS_FILE, 'utf8') || '[]');
        // Giải mã email cho admin
        const usersForAdmin = users.map(u => ({
            ...u,
            email: (() => { try { return decrypt(u.email); } catch { return u.email; } })()
        }));
        res.json(usersForAdmin);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Thống kê doanh thu cho admin
app.get('/api/admin/revenue', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { type = 'day' } = req.query; // type: day|week|month
        const orders = JSON.parse(await fs.promises.readFile(ORDERS_FILE, 'utf8') || '[]');
        const users = JSON.parse(await fs.promises.readFile(USERS_FILE, 'utf8') || '[]');
        const now = new Date();
        let start;
        if (type === 'day') {
            start = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        } else if (type === 'week') {
            const day = now.getDay() || 7;
            start = new Date(now.getFullYear(), now.getMonth(), now.getDate() - day + 1);
        } else if (type === 'month') {
            start = new Date(now.getFullYear(), now.getMonth(), 1);
        } else {
            return res.status(400).json({ error: 'Invalid type' });
        }
        // Đơn hàng trong khoảng thời gian
        const filteredOrders = orders.filter(o => new Date(o.createdAt) >= start);
        // Tổng tiền bán acc (chỉ đơn đã duyệt hoặc hoàn thành)
        const totalSales = filteredOrders.filter(o => o.status === 'approved' || o.status === 'completed')
            .reduce((sum, o) => sum + (o.accountPrice || 0), 0);
        // Tổng số đơn
        const totalOrders = filteredOrders.length;
        // Số user mới
        const newUsers = users.filter(u => new Date(u.createdAt) >= start).length;
        // Tổng tiền nạp (giả sử log nạp tiền là các thay đổi balance tăng, cần log riêng nếu muốn chính xác)
        // Ở đây chỉ trả về 0, sẽ bổ sung sau nếu có log nạp tiền
        res.json({
            type,
            from: start,
            to: now,
            totalSales,
            totalOrders,
            newUsers,
            totalDeposit: 0 // placeholder
        });
    } catch (error) {
        console.error('Error revenue:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Sửa thông tin user (chỉ cho admin)
app.put('/api/users/:username', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { username } = req.params;
        const { email, balance, role } = req.body;
        const users = JSON.parse(await fs.promises.readFile(USERS_FILE, 'utf8') || '[]');
        const user = users.find(u => u.username === username);
        if (!user) return res.status(404).json({ error: 'User not found' });

        if (email) user.email = encrypt(email);
        if (typeof balance === 'number') user.balance = balance;
        if (role) user.role = role;

        await fs.promises.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Tạo đơn hàng mới
app.post('/api/orders', authenticateToken, async (req, res) => {
    try {
        const order = req.body;
        // Đọc danh sách đơn hàng hiện tại
        let orders = [];
        try {
            const data = await fs.promises.readFile(ORDERS_FILE, 'utf8');
            orders = JSON.parse(data || '[]');
        } catch (e) {
            orders = [];
        }

        // Trừ tiền user
        const users = JSON.parse(await fs.promises.readFile(USERS_FILE, 'utf8') || '[]');
        const userIdx = users.findIndex(u => u.username === req.user.id);
        if (userIdx === -1) return res.status(404).json({ error: 'User not found' });

        const price = order.accountPrice || 0;
        if (users[userIdx].balance < price) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        users[userIdx].balance -= price;
        await fs.promises.writeFile(USERS_FILE, JSON.stringify(users, null, 2));

        // Thêm đơn hàng mới
        orders.push(order);
        await fs.promises.writeFile(ORDERS_FILE, JSON.stringify(orders, null, 2));
        
        // Ẩn acc khỏi ACC.txt khi có đơn hàng chờ duyệt
        if (order.accountId) {
            const accData = await fs.promises.readFile(ACCOUNTS_FILE, 'utf8');
            const accLines = accData.trim().split('\n');
            const idx = accLines.findIndex(line => generateAccountId(line) === order.accountId);
            if (idx !== -1) {
                const [removed] = accLines.splice(idx, 1);
                await fs.promises.writeFile(ACCOUNTS_FILE, accLines.join('\n'));
                // Thêm vào hidden_accounts.txt
                let hidden = '';
                try {
                    hidden = await fs.promises.readFile(HIDDEN_ACCOUNTS_FILE, 'utf8');
                } catch {}
                const hiddenLines = hidden ? hidden.trim().split('\n') : [];
                hiddenLines.push(removed);
                await fs.promises.writeFile(HIDDEN_ACCOUNTS_FILE, hiddenLines.join('\n'));
            }
        }
        res.json({ success: true, order });
    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Upload tài khoản shop (chỉ cho admin)
app.post('/api/upload-accounts', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { accounts } = req.body;
        if (!accounts || typeof accounts !== 'string') {
            return res.status(400).json({ error: 'Invalid accounts data' });
    }
        await fs.promises.writeFile(ACCOUNTS_FILE, accounts.trim());
        res.json({ success: true });
    } catch (error) {
        console.error('Error uploading accounts:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Decrypt endpoint for admin (requires authentication)
app.post('/api/decrypt', authenticateToken, (req, res) => {
    try {
        const { encryptedData } = req.body;
        if (!encryptedData) {
            return res.status(400).json({ error: 'Missing encryptedData' });
        }
        // Use the user's encryption key from the JWT
        const decrypted = decrypt(encryptedData, req.encryptionKey);
        res.json({ success: true, decryptedData: decrypted });
    } catch (error) {
        console.error('Decrypt error:', error);
        res.status(400).json({ error: 'Failed to decrypt data' });
    }
});

// Khôi phục tài khoản về shop (chỉ cho admin)
app.post('/api/accounts/restore', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { accountId } = req.body;
        if (!accountId) return res.status(400).json({ error: 'Missing accountId' });

        // Đọc hidden_accounts.txt
        let hidden = '';
        try {
            hidden = await fs.promises.readFile(HIDDEN_ACCOUNTS_FILE, 'utf8');
        } catch {}
        let hiddenLines = hidden
            ? hidden.split('\n').map(l => l.trim()).filter(l => l)
            : [];
        const idx = hiddenLines.findIndex(line => generateAccountId(line) === accountId);
        if (idx === -1) {
            // Không trả lỗi, chỉ báo đã khôi phục
            return res.json({ success: true, alreadyRestored: true });
        }
        const [restored] = hiddenLines.splice(idx, 1);

        // Thêm lại vào ACC.txt
        let accData = '';
        try {
            accData = await fs.promises.readFile(ACCOUNTS_FILE, 'utf8');
        } catch {}
        let accLines = accData
            ? accData.split('\n').map(l => l.trim()).filter(l => l)
            : [];
        accLines.push(restored.trim());

        // Ghi lại file, đảm bảo không có dòng trống
        await fs.promises.writeFile(ACCOUNTS_FILE, accLines.join('\n'));
        await fs.promises.writeFile(HIDDEN_ACCOUNTS_FILE, hiddenLines.join('\n'));

        res.json({ success: true, restored });
    } catch (error) {
        console.error('Restore account error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Cập nhật trạng thái đơn hàng (chỉ cho admin)
app.put('/api/orders/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { status, adminNote } = req.body;
        let orders = [];
        try {
            const data = await fs.promises.readFile(ORDERS_FILE, 'utf8');
            orders = JSON.parse(data || '[]');
        } catch (e) {
            return res.status(404).json({ error: 'Orders not found' });
        }
        const idx = orders.findIndex(o => o.id == id);
        if (idx === -1) return res.status(404).json({ error: 'Order not found' });

        if (status) orders[idx].status = status;
        if (adminNote !== undefined) orders[idx].adminNote = adminNote;

        await fs.promises.writeFile(ORDERS_FILE, JSON.stringify(orders, null, 2));
        res.json({ success: true, order: orders[idx] });
    } catch (error) {
        console.error('Update order error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// Initialize admin user if not exists
if (!fs.existsSync(USERS_FILE)) {
    const adminPassword = process.env.ADMIN_PASSWORD || crypto.randomBytes(16).toString('hex');
    bcrypt.hash(adminPassword, 12).then(hashedPassword => {
        const initialUsers = [{
            username: 'admin',
            password: hashedPassword,
            email: encrypt('admin@example.com'),
            role: 'admin',
            balance: 1000000,
            createdAt: new Date().toISOString()
        }];
        fs.writeFileSync(USERS_FILE, JSON.stringify(initialUsers, null, 2));
        console.log('Admin account created with password:', adminPassword);
    });
}

// --- Tạo user admin mới: thuanad / 123123@ ---
(async () => {
  const bcrypt = require('bcryptjs');
  const fs = require('fs');
  const path = require('path');
  const crypto = require('crypto');
  // Lấy hàm encrypt từ file này
  function encrypt(text, userKey = ENCRYPTION_KEY) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = crypto.pbkdf2Sync(userKey, salt, 2145, 32, 'sha512');
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
  }
  const USERS_FILE = path.join(__dirname, 'users.json');
  const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  if (!users.find(u => u.username === 'thuanad')) {
    const hashedPassword = await bcrypt.hash('123123@', 12);
    const email = encrypt('thuanad@example.com');
    users.push({
      username: 'thuanad',
      password: hashedPassword,
      email: email,
      role: 'admin',
      balance: 0,
      createdAt: new Date().toISOString()
    });
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    console.log('Đã tạo user admin: thuanad / 123123@');
  } else {
    console.log('User thuanad đã tồn tại.');
  }
})();

// Nạp tiền cho chính user (user tự thao tác, không cần admin)
app.post('/api/users/me/deposit', authenticateToken, async (req, res) => {
    try {
        const { amount } = req.body;
        if (typeof amount !== 'number' || amount <= 0) {
            return res.status(400).json({ error: 'Invalid amount' });
        }
        const users = JSON.parse(await fs.promises.readFile(USERS_FILE, 'utf8') || '[]');
        const user = users.find(u => u.username === req.user.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        user.balance += amount;
        await fs.promises.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
        res.json({ success: true, balance: user.balance });
    } catch (error) {
        console.error('Deposit error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.listen(PORT, () => {
    console.log(`Secure server running at http://localhost:${PORT}`);
}); 