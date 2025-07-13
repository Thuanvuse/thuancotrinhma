import requests

def parse_acc_line(line):
    parts = line.strip().split('|')
    if len(parts) < 6:
        return None
    username = parts[2]
    password = parts[3]
    # Lấy balance, nếu không phải số thì để 0
    try:
        balance = int(parts[5])
    except:
        balance = 0
    return {
        "username": username,
        "password": password,
        "email": f"{username}@example.com",
        "role": "user",
        "balance": balance
    }

accounts = []
with open("ACC.txt", encoding="utf-8") as f:
    for line in f:
        user = parse_acc_line(line)
        if user:
            accounts.append(user)

print(f"Đã parse được {len(accounts)} tài khoản, bắt đầu upload...")

resp = requests.post(
    "http://localhost:3000/api/upload-accounts",
    json={"accounts": accounts}
)

print("Kết quả:", resp.status_code, resp.text)