# OKVIP Shop - Hệ thống bán tài khoản game

## 🌟 Tính năng chính
- Đăng ký/Đăng nhập người dùng
- Mua tài khoản game với nhiều website hỗ trợ (OK9, 78win, F168, MB66, QQ88)
- Quản lý tài khoản admin
- Lịch sử mua hàng
- Nạp tiền và quản lý số dư
- Giao diện responsive với dark mode

## 🚀 Hướng dẫn Deploy

### 1. Deploy lên Render.com (Miễn phí)

1. **Tạo tài khoản Render.com**
   - Truy cập https://render.com
   - Đăng ký tài khoản miễn phí

2. **Tạo Web Service**
   - Click "New +" → "Web Service"
   - Connect với GitHub repository của bạn
   - Chọn repository chứa code

3. **Cấu hình**
   - **Name**: okvip-shop
   - **Environment**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Plan**: Free

4. **Deploy**
   - Click "Create Web Service"
   - Đợi build và deploy hoàn tất
   - Lấy URL từ dashboard

### 2. Deploy lên Railway.app (Miễn phí)

1. **Tạo tài khoản Railway**
   - Truy cập https://railway.app
   - Đăng ký với GitHub

2. **Deploy**
   - Click "New Project"
   - Chọn "Deploy from GitHub repo"
   - Chọn repository
   - Railway sẽ tự động detect và deploy

### 3. Deploy lên Heroku (Có phí)

1. **Cài đặt Heroku CLI**
   ```bash
   npm install -g heroku
   ```

2. **Login và tạo app**
   ```bash
   heroku login
   heroku create okvip-shop
   ```

3. **Deploy**
   ```bash
   git add .
   git commit -m "Initial commit"
   git push heroku main
   ```

## 📁 Cấu trúc file

```
SHOPOKVIP/
├── server.js          # Backend server
├── index.html         # Frontend chính
├── admin.html         # Admin panel
├── users.json         # Dữ liệu người dùng
├── orders.json        # Dữ liệu đơn hàng
├── ACC.txt           # Danh sách tài khoản
├── hidden_accounts.txt # Tài khoản tạm ẩn
├── package.json       # Dependencies
└── README.md         # Hướng dẫn
```

## 🔧 Cài đặt local

```bash
# Clone repository
git clone <your-repo-url>
cd SHOPOKVIP

# Cài đặt dependencies
npm install

# Chạy server
npm start

# Truy cập http://localhost:3000
```

## 👤 Tài khoản Admin mặc định
- **Username**: admin
- **Password**: admin123
- **Email**: admin@okvip.com

## 📝 Lưu ý quan trọng

1. **Bảo mật**: Đổi mật khẩu admin sau khi deploy
2. **Backup**: Sao lưu dữ liệu users.json và orders.json thường xuyên
3. **SSL**: Nên sử dụng HTTPS cho production
4. **Database**: Có thể nâng cấp lên database thực (MongoDB, PostgreSQL) khi cần

## 🆘 Hỗ trợ

Nếu gặp vấn đề khi deploy, hãy kiểm tra:
- Logs trong dashboard của platform
- Đảm bảo tất cả file được commit lên Git
- Kiểm tra port và environment variables
