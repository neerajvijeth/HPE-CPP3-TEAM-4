# 🔐 SecureVault Fixed — Secure Password Manager

## 📌 Project Overview

SecureVault Fixed is a **secure version of a password manager application** developed to demonstrate and mitigate common web vulnerabilities from the OWASP Top 10.

This version improves upon a vulnerable baseline by implementing:

* 🔒 Strong password hashing using **bcrypt**
* 🔐 Secure encryption for stored credentials (**AES-based vault encryption**)
* 🛡 Protection against **SSRF (Server-Side Request Forgery)**
* 📂 Secure file upload validation (restricted types & size limits)
* 🚫 Prevention of brute-force attacks via **account lockout**
* 📊 Security logging & monitoring (OWASP A09)
* 🌐 Secure HTTP headers (CSP, XSS protection, etc.)

The project is designed for **DevSecOps demonstration**, showing both insecure and hardened implementations.

---

## 📦 Prerequisites

* Python 3.10+
* Docker Desktop (running)

---

## 🧱 1. Initial Setup (FIRST TIME ONLY)

```powershell
cd securevault_fixed
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

---

## 🐘 2. Setup PostgreSQL (Docker)

### ▶️ Create DB container (RUN ONCE)

```powershell
docker run -d --name securevault_secure_db -e POSTGRES_DB=securevault -e POSTGRES_USER=securevault -e POSTGRES_PASSWORD=securevault -p 5434:5432 postgres:14
```

---

### 🔁 Start DB (EVERY TIME YOU RESTART SYSTEM)

```powershell
docker start securevault_secure_db
```

---

### 🔍 Verify DB

```powershell
docker ps
```

Expected:

```
0.0.0.0:5434->5432/tcp
```

---

## 🔐 3. Environment Setup

### 📄 Create `.env` file in root:

```
FLASK_APP=run.py
FLASK_ENV=development
DEBUG=False

DATABASE_URL=postgresql://securevault:securevault@localhost:5434/securevault

SECRET_KEY=your_secret_key_here
VAULT_ENCRYPTION_KEY=your_encryption_key_here

LOGGING_ENABLED=True
```

---

### 🔑 Generate keys

```powershell
$env:PYTHONPATH="."
$env:FLASK_APP="run.py"
flask generate-keys
```

👉 Copy generated keys into `.env`

---

## 🧬 4. Database Setup (FIRST TIME or after changes)

```powershell
Remove-Item -Recurse -Force migrations

$env:PYTHONPATH="."
$env:FLASK_APP="run.py"
$env:DATABASE_URL="postgresql://securevault:securevault@localhost:5434/securevault"

flask db init
flask db migrate -m "hardened"
flask db upgrade
flask seed-db
```

---

## ▶️ 5. Run the App

```powershell
$env:PYTHONPATH="."
$env:FLASK_APP="run.py"
$env:FLASK_RUN_PORT=5001
$env:DATABASE_URL="postgresql://securevault:securevault@localhost:5434/securevault"

flask run
```

---

## 🌐 Access Application

Open in browser:

```
http://127.0.0.1:5001
```

---

## 🔐 Demo Credentials

```
admin / Admin@SecureVault1!
alice / Alice@Secure123!
bob   / Bob@Secure456!
```

---

## 🔄 6. Restart Guide (EVERY TIME)

```powershell
cd securevault_fixed
venv\Scripts\activate

docker start securevault_secure_db

$env:PYTHONPATH="."
$env:FLASK_APP="run.py"
$env:FLASK_RUN_PORT=5001
$env:DATABASE_URL="postgresql://securevault:securevault@localhost:5434/securevault"

flask run
```

---

## 🧹 7. Full Reset (if something breaks)

```powershell
docker rm -f securevault_secure_db

docker run -d --name securevault_secure_db -e POSTGRES_DB=securevault -e POSTGRES_USER=securevault -e POSTGRES_PASSWORD=securevault -p 5434:5432 postgres:14

Remove-Item -Recurse -Force migrations

$env:PYTHONPATH="."
$env:FLASK_APP="run.py"
$env:DATABASE_URL="postgresql://securevault:securevault@localhost:5434/securevault"

flask db init
flask db migrate -m "fresh"
flask db upgrade
flask seed-db
```

---

## ⚠️ Common Errors

* ❌ Wrong port → use **5434 everywhere**
* ❌ No module named app → run:

  ```powershell
  $env:PYTHONPATH="."
  ```
* ❌ DB connection failed → ensure Docker container is running

---

## 🎯 Quick Summary

```
Start Docker → Activate venv → Set env → Run Flask
```

---

## 🧠 Key Learning Outcome

This project demonstrates how insecure design decisions can be systematically fixed using **secure coding practices, proper configuration, and defensive programming techniques** aligned with OWASP standards.
