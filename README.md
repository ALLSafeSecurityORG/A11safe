# 🛡️ Locater: Flask Honeypot for Suspicious Content Detection

![Python](https://img.shields.io/badge/Python-3.8%2B-yellow.svg)
![Flask](https://img.shields.io/badge/Flask-2.x-blue.svg)
![Status](https://img.shields.io/badge/Status-Development-red)

## 🚀 Overview

**Locater** is a lightweight Flask-based honeypot system designed to detect, log, and alert on suspicious or malicious file uploads and payloads. It inspects the content of uploaded files, logs activity with geolocation metadata, and sends alerts via **Email** and **Discord** when potential threats are detected.

## 🔗 Live Demo

Check out the live website here: [My Project Site](https://a11safe.onrender.com/)

## For adminlogin
```
admin
SuperSecure@123
```    
---

## 🔍 Features

- 📜 Pattern-based detection for XSS, RCE, file uploads, reverse shells, etc.
- 🌍 Geolocation lookup using IP API
- 🔒 IP extraction behind proxies (supports Cloudflare)
- 📧 Email and 🧵 Discord webhook alerts
- 📁 Detailed log files (attack + general)
- ☁️ Environment variable support for easy configuration

---

## 🧠 How It Works

1. User uploads or submits content (via a note or file).
2. Content is checked against a comprehensive list of **regex patterns** for known attack signatures.
3. Real client IP is extracted from headers (supporting trusted proxies).
4. GeoIP info is fetched from the client's IP.
5. Activity is logged with full HTTP metadata.
6. If an attack is detected:
   - It is logged in `attacks.log`
   - An alert is sent to Discord & Email

---

## 🗂️ File Structure

```
.
├── app.py                # Main Flask application
├── content_detect.py     # Core detection logic
├── templates/
│   └── index.html        # Frontend template
├── logs/
│   ├── attacks.log       # Suspicious activity log
│   └── general.log       # Normal usage log
```

---

## ⚠️ Attack Patterns Detected

Includes detection for:

| Category           | Example Pattern                    |
|--------------------|------------------------------------|
| XSS                | `<script>alert(1)</script>`        |
| Command Injection  | `; whoami`                         |
| Reverse Shells     | `bash -i >& /dev/tcp/...`          |
| File Upload Abuse  | `.php`, `.jsp`, `.exe`, etc.       |
| Base64 Abuse       | `echo <base64> | base64 -d | sh`   |
| LFI / RFI          | `../../etc/passwd`, `eval(...)`    |
| Windows Commands   | `cmd.exe`, `powershell.exe`        |

---

## 📨 Environment Variables

Set these in your environment or `.env` file:

```bash
SENDER_EMAIL=your_email@gmail.com
EMAIL_PASSWORD=your_email_password_or_app_password
RECEIVER_EMAILS=receiver1@example.com,receiver2@example.com
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

---

## 📥 Example `.env` File

```env
SENDER_EMAIL=allsafeallsafe612@gmail.com
EMAIL_PASSWORD=htsneaayrqwutldg
RECEIVER_EMAILS=unknownzero51@gmail.com,aryanbhandari2431@gmail.com
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

---

## 🏁 Run Locally

```bash
# Install dependencies
pip install flask requests

# Run the Flask app
python app.py
```


## 🧪 Example Code Block

```python
def is_suspicious(content):
    return "<script>" in content
```

---

## 📬 License

MIT License

---

## 👨‍💻 Author

Aryan Bhandari — [GitHub](https://github.com/aryanbhandari247)
Priyanshu — [GitHub](https://github.com/priyanxshu999)
