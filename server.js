const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// File paths
const USERS_FILE = 'users.json';
const ORDERS_FILE = 'orders.json';
const ACCOUNTS_FILE = 'ACC.txt';
const HIDDEN_ACCOUNTS_FILE = 'hidden_accounts.txt';

// Đọc danh sách user
app.get('/api/users', (req, res) => {
    fs.readFile(USERS_FILE, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Cannot read users file' });
        res.json(JSON.parse(data || '[]'));
    });
});

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
            res.json({ success: true, user: newUser });
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
        res.json({ success: true, user });
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
            res.json({ success: true, user: users[idx] });
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

// API đọc file ACC.txt
app.get('/api/accounts', (req, res) => {
    const accFile = path.join(__dirname, ACCOUNTS_FILE);
    fs.readFile(accFile, 'utf8', (err, data) => {
        if (err) {
            console.error('Error reading ACC.txt:', err);
            return res.status(500).json({ error: 'Cannot read accounts file' });
        }
        res.json({ data });
    });
});

// API xóa tài khoản (ẩn khỏi shop)
app.post('/api/accounts/hide', (req, res) => {
    const { accountLine } = req.body; // Dòng tài khoản cần ẩn
    const accFile = path.join(__dirname, ACCOUNTS_FILE);
    const hiddenFile = path.join(__dirname, HIDDEN_ACCOUNTS_FILE);
    
    fs.readFile(accFile, 'utf8', (err, data) => {
        if (err) {
            return res.status(500).json({ error: 'Cannot read accounts file' });
        }
        
        const lines = data.split('\n');
        const newLines = lines.filter(line => line.trim() !== accountLine.trim());
        
        // Lưu tài khoản đã ẩn vào file riêng
        fs.appendFile(hiddenFile, accountLine + '\n', (err2) => {
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

// API khôi phục tài khoản (hiện lại trên shop)
app.post('/api/accounts/restore', (req, res) => {
    const { accountLine } = req.body; // Dòng tài khoản cần khôi phục
    const accFile = path.join(__dirname, ACCOUNTS_FILE);
    const hiddenFile = path.join(__dirname, HIDDEN_ACCOUNTS_FILE);
    
    // Thêm tài khoản trở lại ACC.txt
    fs.appendFile(accFile, accountLine + '\n', (err) => {
        if (err) {
            return res.status(500).json({ error: 'Cannot restore account' });
        }
        
        // Xóa khỏi file hidden_accounts.txt
        fs.readFile(hiddenFile, 'utf8', (err2, data) => {
            if (!err2 && data) {
                const lines = data.split('\n');
                const newLines = lines.filter(line => line.trim() !== accountLine.trim());
                fs.writeFile(hiddenFile, newLines.join('\n'), (err3) => {
                    if (err3) {
                        console.error('Error updating hidden accounts file:', err3);
                    }
                });
            }
            res.json({ success: true });
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
        res.json(orders);
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
            res.json({ success: true, order });
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
            res.json({ success: true, order: orders[idx] });
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
        res.json(userOrders);
    });
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