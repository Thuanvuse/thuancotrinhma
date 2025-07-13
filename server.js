const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3001;

// Encryption key (in production, use environment variable)
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your-secret-key-32-chars-long!!';
const ALGORITHM = 'aes-256-cbc';

// Encryption utilities
function encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher(ALGORITHM, ENCRYPTION_KEY);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = textParts.join(':');
    const decipher = crypto.createDecipher(ALGORITHM, ENCRYPTION_KEY);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function generateAccountId(accountLine) {
    return crypto.createHash('md5').update(accountLine).digest('hex').substring(0, 8);
}

// Sanitize order data for API responses
function sanitizeOrder(order) {
    const sanitized = { ...order };
    
    // Remove sensitive account data
    if (sanitized.accountLine) {
        sanitized.accountId = generateAccountId(sanitized.accountLine);
        delete sanitized.accountLine; // Remove sensitive data
    }
    
    // Ensure accountId exists
    if (!sanitized.accountId && sanitized.accountLine) {
        sanitized.accountId = generateAccountId(sanitized.accountLine);
    }
    
    // Mask sensitive user information
    if (sanitized.userEmail) {
        const [local, domain] = sanitized.userEmail.split('@');
        sanitized.userEmail = local.substring(0, 2) + '***@' + domain;
    }
    
    if (sanitized.phoneLast4) {
        sanitized.phoneLast4 = '****';
    }
    
    if (sanitized.gameUsername) {
        sanitized.gameUsername = sanitized.gameUsername.substring(0, 2) + '***';
    }
    
    // Remove balance information from order responses
    delete sanitized.balance;
    
    return sanitized;
}

// Sanitize user data for API responses
function sanitizeUser(user) {
    const sanitized = { ...user };
    
    // Remove password from responses
    delete sanitized.password;
    
    // Mask email for non-admin users
    if (sanitized.email && sanitized.role !== 'admin') {
        const [local, domain] = sanitized.email.split('@');
        sanitized.email = local.substring(0, 2) + '***@' + domain;
    }
    
    // Mask balance for non-admin users
    if (sanitized.balance && sanitized.role !== 'admin') {
        sanitized.balance = Math.floor(sanitized.balance / 1000) * 1000; // Round to nearest 1000
    }
    
    return sanitized;
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// Middleware to check admin role
function requireAdmin(req, res, next) {
    const username = req.body.username || req.query.username;
    if (!username) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    fs.readFile(USERS_FILE, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Cannot read users file' });
        const users = JSON.parse(data || '[]');
        const user = users.find(u => u.username === username);
        if (!user || user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        next();
    });
}

// File paths
const USERS_FILE = 'users.json';
const ORDERS_FILE = 'orders.json';
const ACCOUNTS_FILE = 'ACC.txt';
const HIDDEN_ACCOUNTS_FILE = 'hidden_accounts.txt';

// Đăng ký user mới
app.post('/api/register', (req, res) => {
    const { username, password, email } = req.body;
    fs.readFile(USERS_FILE, 'utf8', (err, data) => {
        let users = [];
        if (!err && data) users = JSON.parse(data);
        if (users.find(u => u.username === username)) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        const newUser = { username, password, email, role: 'user', balance: 0 };
        users.push(newUser);
        fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), err2 => {
            if (err2) return res.status(500).json({ error: 'Cannot save user' });
            res.json({ success: true, user: sanitizeUser(newUser) });
        });
    });
});

// Đăng nhập
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    fs.readFile(USERS_FILE, 'utf8', (err, data) => {
        let users = [];
        if (!err && data) users = JSON.parse(data);
        const user = users.find(u => u.username === username && u.password === password);
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        res.json({ success: true, user: sanitizeUser(user) });
    });
});

// Sửa user (chỉ cho admin)
app.put('/api/users/:username', (req, res) => {
    const { username } = req.params;
    const { email, balance, role } = req.body;
    fs.readFile(USERS_FILE, 'utf8', (err, data) => {
        let users = [];
        if (!err && data) users = JSON.parse(data);
        const idx = users.findIndex(u => u.username === username);
        if (idx === -1) return res.status(404).json({ error: 'User not found' });
        users[idx] = { ...users[idx], email, balance, role };
        fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), err2 => {
            if (err2) return res.status(500).json({ error: 'Cannot update user' });
            res.json({ success: true, user: sanitizeUser(users[idx]) });
        });
    });
});

// Xóa user (chỉ cho admin)
app.delete('/api/users/:username', (req, res) => {
    const { username } = req.params;
    fs.readFile(USERS_FILE, 'utf8', (err, data) => {
        let users = [];
        if (!err && data) users = JSON.parse(data);
        const idx = users.findIndex(u => u.username === username);
        if (idx === -1) return res.status(404).json({ error: 'User not found' });
        users.splice(idx, 1);
        fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), err2 => {
            if (err2) return res.status(500).json({ error: 'Cannot delete user' });
            res.json({ success: true });
        });
    });
});

// API upload nhiều tài khoản (thêm hàng loạt)
app.post('/api/upload-accounts', (req, res) => {
    const { accounts } = req.body; // accounts là string content từ file ACC.txt
    if (!accounts || typeof accounts !== 'string') {
        return res.status(400).json({ error: 'accounts must be a string' });
    }
    
    const accFile = path.join(__dirname, ACCOUNTS_FILE);
    
    // Đọc file hiện tại
    fs.readFile(accFile, 'utf8', (err, data) => {
        let existingAccounts = [];
        if (!err && data) {
            existingAccounts = data.trim().split('\n').filter(line => line.trim());
        }
        
        // Parse tài khoản mới
        const newAccounts = accounts.trim().split('\n').filter(line => line.trim());
        
        // Thêm tài khoản mới vào cuối file
        const allAccounts = [...existingAccounts, ...newAccounts];
        
        // Ghi lại file
        fs.writeFile(accFile, allAccounts.join('\n'), err2 => {
            if (err2) return res.status(500).json({ error: 'Cannot save accounts' });
            res.json({ success: true, added: newAccounts.length, total: allAccounts.length });
        });
    });
});

// API đọc file ACC.txt (public, chỉ trả về id, points, username (mask), websites)
app.get('/api/accounts', (req, res) => {
    const accFile = path.join(__dirname, ACCOUNTS_FILE);
    fs.readFile(accFile, 'utf8', (err, data) => {
        if (err) {
            console.error('Error reading ACC.txt:', err);
            return res.status(500).json({ error: 'Cannot read accounts file' });
        }
        const accounts = data.trim().split('\n').filter(line => line.trim());
        const accountIds = accounts.map(account => {
            const parts = account.split('|');
            const id = generateAccountId(account);
            const points = parts[5] || '0';
            const username = parts[2] || '';
            const maskedUsername = username.length > 2 ? username.substring(0,2) + '****' : username + '****';
            const websites = parts[7] || '';
            return { id, points, username: maskedUsername, websites };
        });
        res.json({ 
            total: accounts.length,
            accounts: accountIds
        });
    });
});

// API xóa tài khoản (ẩn khỏi shop) - sử dụng accountId
app.post('/api/accounts/hide', (req, res) => {
    const { accountId } = req.body; // ID tài khoản cần ẩn
    const accFile = path.join(__dirname, ACCOUNTS_FILE);
    const hiddenFile = path.join(__dirname, HIDDEN_ACCOUNTS_FILE);
    
    fs.readFile(accFile, 'utf8', (err, data) => {
        if (err) {
            return res.status(500).json({ error: 'Cannot read accounts file' });
        }
        
        const lines = data.split('\n').filter(line => line.trim());
        const accountToHide = lines.find(line => generateAccountId(line) === accountId);
        
        if (!accountToHide) {
            return res.status(404).json({ error: 'Account not found' });
        }
        
        const newLines = lines.filter(line => generateAccountId(line) !== accountId);
        
        // Lưu tài khoản đã ẩn vào file riêng
        fs.appendFile(hiddenFile, accountToHide + '\n', (err2) => {
            if (err2) {
                console.error('Error saving hidden account:', err2);
            }
        });
        
        // Cập nhật file ACC.txt
        fs.writeFile(accFile, newLines.join('\n'), (err3) => {
            if (err3) {
                return res.status(500).json({ error: 'Cannot update accounts file' });
            }
            res.json({ success: true });
        });
    });
});

// API khôi phục tài khoản (hiện lại trên shop) - sử dụng accountId
app.post('/api/accounts/restore', (req, res) => {
    const { accountId } = req.body; // ID tài khoản cần khôi phục
    const accFile = path.join(__dirname, ACCOUNTS_FILE);
    const hiddenFile = path.join(__dirname, HIDDEN_ACCOUNTS_FILE);
    
    // Tìm tài khoản trong file hidden
    fs.readFile(hiddenFile, 'utf8', (err, data) => {
        if (err) {
            return res.status(500).json({ error: 'Cannot read hidden accounts file' });
        }
        
        const lines = data.split('\n').filter(line => line.trim());
        const accountToRestore = lines.find(line => generateAccountId(line) === accountId);
        
        if (!accountToRestore) {
            return res.status(404).json({ error: 'Account not found in hidden list' });
        }
        
        // Thêm tài khoản trở lại ACC.txt
        fs.appendFile(accFile, accountToRestore + '\n', (err2) => {
            if (err2) {
                return res.status(500).json({ error: 'Cannot restore account' });
            }
            
            // Xóa khỏi file hidden_accounts.txt
            const newLines = lines.filter(line => generateAccountId(line) !== accountId);
            fs.writeFile(hiddenFile, newLines.join('\n'), (err3) => {
                if (err3) {
                    console.error('Error updating hidden accounts file:', err3);
                }
            });
            res.json({ success: true });
        });
    });
});

// API lấy thông tin chi tiết tài khoản (chỉ cho admin, dữ liệu được mã hóa)
app.get('/api/accounts/:accountId/details', (req, res) => {
    const { accountId } = req.params;
    const { username } = req.query;
    
    if (!username) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    // Kiểm tra quyền admin
    fs.readFile(USERS_FILE, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Cannot read users file' });
        const users = JSON.parse(data || '[]');
        const user = users.find(u => u.username === username);
        if (!user || user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        // Tiếp tục xử lý nếu là admin
        const accFile = path.join(__dirname, ACCOUNTS_FILE);
        
        fs.readFile(accFile, 'utf8', (err2, data2) => {
            if (err2) {
                return res.status(500).json({ error: 'Cannot read accounts file' });
            }
            
            const accounts = data2.trim().split('\n').filter(line => line.trim());
            const account = accounts.find(acc => generateAccountId(acc) === accountId);
            
            if (!account) {
                return res.status(404).json({ error: 'Account not found' });
            }
            
            // Trả về dữ liệu được mã hóa
            res.json({ 
                success: true,
                encryptedData: encrypt(account)
            });
        });
    });
});

// API admin - lấy dữ liệu chi tiết orders (không sanitized)
app.get('/api/admin/orders', (req, res) => {
    const { username } = req.query;
    if (!username) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    fs.readFile(USERS_FILE, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Cannot read users file' });
        const users = JSON.parse(data || '[]');
        const user = users.find(u => u.username === username);
        if (!user || user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        fs.readFile(ORDERS_FILE, 'utf8', (err2, data2) => {
            if (err2 && err2.code !== 'ENOENT') {
                return res.status(500).json({ error: 'Cannot read orders file' });
            }
            const orders = data2 ? JSON.parse(data2) : [];
            res.json(orders); // Return full data for admin
        });
    });
});

// API admin - lấy dữ liệu chi tiết users (không sanitized)
app.get('/api/admin/users', (req, res) => {
    const { username } = req.query;
    if (!username) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    fs.readFile(USERS_FILE, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Cannot read users file' });
        const users = JSON.parse(data || '[]');
        const user = users.find(u => u.username === username);
        if (!user || user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        res.json(users); // Return full data for admin
    });
});

// API admin - lấy dữ liệu chi tiết accounts (không sanitized)
app.get('/api/admin/accounts', (req, res) => {
    const { username } = req.query;
    if (!username) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    fs.readFile(USERS_FILE, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Cannot read users file' });
        const users = JSON.parse(data || '[]');
        const user = users.find(u => u.username === username);
        if (!user || user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        const accFile = path.join(__dirname, ACCOUNTS_FILE);
        fs.readFile(accFile, 'utf8', (err2, data2) => {
            if (err2) {
                console.error('Error reading ACC.txt:', err2);
                return res.status(500).json({ error: 'Cannot read accounts file' });
            }
            res.json({ data: data2 }); // Return full data for admin
        });
    });
});

// API admin - lấy danh sách tài khoản đã ẩn
app.get('/api/admin/hidden-accounts', (req, res) => {
    const { username } = req.query;
    if (!username) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    fs.readFile(USERS_FILE, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Cannot read users file' });
        const users = JSON.parse(data || '[]');
        const user = users.find(u => u.username === username);
        if (!user || user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        const hiddenFile = path.join(__dirname, HIDDEN_ACCOUNTS_FILE);
        fs.readFile(hiddenFile, 'utf8', (err2, data2) => {
            if (err2 && err2.code !== 'ENOENT') {
                return res.status(500).json({ error: 'Cannot read hidden accounts file' });
            }
            const accounts = data2 ? data2.trim().split('\n').filter(line => line.trim()) : [];
            const accountIds = accounts.map(account => ({
                id: generateAccountId(account),
                points: account.split('|')[4] || '0',
                websites: account.split('|')[7] || ''
            }));
            res.json({ 
                total: accounts.length,
                accounts: accountIds
            });
        });
    });
});

// API quản lý đơn hàng
app.get('/api/orders', (req, res) => {
    fs.readFile(ORDERS_FILE, 'utf8', (err, data) => {
        if (err && err.code !== 'ENOENT') {
            return res.status(500).json({ error: 'Cannot read orders file' });
        }
        const orders = data ? JSON.parse(data) : [];
        const sanitizedOrders = orders.map(order => sanitizeOrder(order));
        res.json(sanitizedOrders);
    });
});

// Tạo đơn hàng mới
app.post('/api/orders', (req, res) => {
    const order = req.body;
    fs.readFile(ORDERS_FILE, 'utf8', (err, data) => {
        let orders = [];
        if (!err && data) orders = JSON.parse(data);
        orders.push(order);
        fs.writeFile(ORDERS_FILE, JSON.stringify(orders, null, 2), err2 => {
            if (err2) return res.status(500).json({ error: 'Cannot save order' });
            res.json({ success: true, order: sanitizeOrder(order) });
        });
    });
});

// Cập nhật trạng thái đơn hàng
app.put('/api/orders/:id', (req, res) => {
    const { id } = req.params;
    const { status, adminNote } = req.body;
    fs.readFile(ORDERS_FILE, 'utf8', (err, data) => {
        let orders = [];
        if (!err && data) orders = JSON.parse(data);
        const idx = orders.findIndex(o => o.id === id);
        if (idx === -1) return res.status(404).json({ error: 'Order not found' });
        
        const order = orders[idx];
        orders[idx] = { ...order, status, adminNote, updatedAt: new Date().toISOString() };
        
        // Nếu từ chối đơn hàng, hoàn tiền cho người dùng
        if (status === 'rejected') {
            const newBalance = order.balance + order.accountPrice;
            fs.readFile(USERS_FILE, 'utf8', (err2, data2) => {
                let users = [];
                if (!err2 && data2) users = JSON.parse(data2);
                const userIdx = users.findIndex(u => u.username === order.userId);
                if (userIdx !== -1) {
                    users[userIdx].balance = newBalance;
                    fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), (err3) => {
                        if (err3) {
                            console.error('Error updating user balance:', err3);
                        }
                    });
                }
            });
        }
        
        fs.writeFile(ORDERS_FILE, JSON.stringify(orders, null, 2), err2 => {
            if (err2) return res.status(500).json({ error: 'Cannot update order' });
            res.json({ success: true, order: sanitizeOrder(orders[idx]) });
        });
    });
});

// Xóa đơn hàng
app.delete('/api/orders/:id', (req, res) => {
    const { id } = req.params;
    fs.readFile(ORDERS_FILE, 'utf8', (err, data) => {
        let orders = [];
        if (!err && data) orders = JSON.parse(data);
        const idx = orders.findIndex(o => o.id === id);
        if (idx === -1) return res.status(404).json({ error: 'Order not found' });
        orders.splice(idx, 1);
        fs.writeFile(ORDERS_FILE, JSON.stringify(orders, null, 2), err2 => {
            if (err2) return res.status(500).json({ error: 'Cannot delete order' });
            res.json({ success: true });
        });
    });
});

// Lấy lịch sử đơn hàng của người dùng
app.get('/api/orders/user/:username', (req, res) => {
    const { username } = req.params;
    fs.readFile(ORDERS_FILE, 'utf8', (err, data) => {
        if (err && err.code !== 'ENOENT') {
            return res.status(500).json({ error: 'Cannot read orders file' });
        }
        const orders = data ? JSON.parse(data) : [];
        const userOrders = orders.filter(order => order.userId === username);
        const sanitizedUserOrders = userOrders.map(order => sanitizeOrder(order));
        res.json(sanitizedUserOrders);
    });
});

// API giải mã dữ liệu (chỉ cho admin)
app.post('/api/decrypt', (req, res) => {
    const { encryptedData } = req.body;
    if (!encryptedData) {
        return res.status(400).json({ error: 'Encrypted data is required' });
    }
    
    try {
        const decryptedData = decrypt(encryptedData);
        res.json({ success: true, decryptedData });
    } catch (error) {
        res.status(400).json({ error: 'Invalid encrypted data' });
    }
});

// Khởi tạo file users.json nếu chưa có
if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify([
        { username: 'thuanjqka', password: 'thuanjqka', email: 'admin@okvip.com', role: 'admin', balance: 1000000 }
    ], null, 2));
}

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
}); 