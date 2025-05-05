import re
import os
import requests
import smtplib
import ipaddress
import logging
from flask import request
from email.mime.text import MIMEText
from threading import Thread

# ============================
# Email & Discord alert settings
# ============================
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "allsafeallsafe612@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "htsneaayrqwutldg")
RECEIVER_EMAILS = os.getenv("RECEIVER_EMAILS", "unknownzero51@gmail.com,aryanbhandari2431@gmail.com").split(",")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/1367935673419694290/ZsrM2jsXscoda4GrJoPNYRNScJkW8tfa_FmlW5lfEp86VR4n_-AoDtbsRNizvaerRDvN")

# ============================
# Logging setup
# ============================
attack_logger = logging.getLogger("attack_logger")
attack_logger.setLevel(logging.INFO)
handler = logging.FileHandler("logs/attacks.log")
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
if not any(isinstance(h, logging.FileHandler) and h.baseFilename == handler.baseFilename for h in attack_logger.handlers):
    attack_logger.addHandler(handler)

# ============================
# Trusted Proxies
# ============================
TRUSTED_PROXIES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"
]

def is_trusted_proxy(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in TRUSTED_PROXIES:
            if ip_obj in ipaddress.ip_network(net):
                return True
    except ValueError:
        pass
    return False

# ============================
# Utility Functions
# ============================
def get_real_ip():
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    x_real_ip = request.headers.get("X-Real-IP")
    remote_ip = request.remote_addr

    if is_trusted_proxy(remote_ip) and x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    elif x_real_ip:
        return x_real_ip.strip()
    else:
        return remote_ip

def get_geolocation(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = res.json()
        if data.get("status") == "success":
            return f"{data.get('country', '')}, {data.get('regionName', '')}, {data.get('city', '')}, ISP: {data.get('isp', '')}"
    except Exception:
        pass
    return "Geolocation not available"

def send_discord_alert(message):
    def _send():
        try:
            requests.post(DISCORD_WEBHOOK_URL, json={"content": message}, timeout=5)
        except Exception:
            pass
    Thread(target=_send).start()

def send_email_alert(subject, message):
    def _send():
        try:
            msg = MIMEText(message)
            msg["Subject"] = subject
            msg["From"] = SENDER_EMAIL
            msg["To"] = ", ".join(RECEIVER_EMAILS)

            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(SENDER_EMAIL, EMAIL_PASSWORD)
                server.sendmail(SENDER_EMAIL, RECEIVER_EMAILS, msg.as_string())
        except Exception:
            pass
    Thread(target=_send).start()

# ============================
# SQL Injection Detection
# ============================
def detect_sql_injection(email, password, proxy_ip):
    patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"(\b(OR|AND)\b\s+[\w\W]*\=)",
        r"(\bUNION\b.*\bSELECT\b)",
        r"(\bSELECT\b.*\bFROM\b)",
        r"(\bINSERT\b|\bUPDATE\b|\bDELETE\b)",
        r"(\bDROP\b\s+\bTABLE\b)",
        r"(\bSLEEP\s*\(\s*\d+\s*\))",
        r"(\bWAITFOR\s+DELAY\b)",
        r"(\bEXEC(\s+|UTE)\b)",
        r"(\bINFORMATION_SCHEMA\b)",
        r"(\bCAST\s*\()",
        r"(\bCONVERT\s*\()",
        r"(\bHAVING\b\s+\d+=\d+)",
        r"(\bLIKE\s+['\"]?%\w+%['\"]?)",
        r"(\bBENCHMARK\s*\(\s*\d+\,)",
        r"(\bOUTFILE\b|\bDUMPFILE\b|\bINTO\b\s+\bFILE\b)",
        r"(\bLOAD_FILE\s*\()",
        r"(\bGROUP\s+BY\b\s+[\w\W]*\()",
        r"(\bXPATH\b\s*\()",
        r"(\bCHAR\s*\(\d+\))"
    ]

    combined = f"{email} {password}"
    for pattern in patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            log_attack(email, proxy_ip, combined)
            return True
    return False

# ============================
# Log & Alert
# ============================
def log_attack(email, proxy_ip, payload):
    real_ip = get_real_ip()
    geo = get_geolocation(real_ip)
    headers = request.headers
    method = request.method
    url = request.url
    filename = request.path.split("/")[-1]

    alert_msg = (
        f"[⚠️ SQL Injection Detected]\n"
        f"REAL_IP       : {real_ip}\n"
        f"PROXY_IP      : {proxy_ip}\n"
        f"GEOLOCATION   : {geo}\n"
        f"FILENAME      : {filename}\n"
        f"METHOD        : {method}\n"
        f"URL           : {url}\n"
        f"USER-AGENT    : {headers.get('User-Agent')}\n"
        f"REFERRER      : {request.referrer}\n"
        f"HOST          : {headers.get('Host')}\n"
        f"ORIGIN        : {headers.get('Origin')}\n"
        f"COOKIE        : {headers.get('Cookie')}\n"
        f"ACCEPT        : {headers.get('Accept')}\n"
        f"ACCEPT-LANG   : {headers.get('Accept-Language')}\n"
        f"ACCEPT-ENC    : {headers.get('Accept-Encoding')}\n"
        f"CONTENT-TYPE  : {headers.get('Content-Type')}\n"
        f"CONTENT-LEN   : {headers.get('Content-Length')}\n"
        f"CONNECTION    : {headers.get('Connection')}\n"
        f"CACHE-CONTROL : {headers.get('Cache-Control')}\n"
        f"SEC-GPC       : {headers.get('Sec-GPC')}\n"
        f"SEC-UA        : {headers.get('Sec-Ch-Ua')}\n"
        f"SEC-UA-PLAT   : {headers.get('Sec-Ch-Ua-Platform')}\n"
        f"SEC-UA-MOB    : {headers.get('Sec-Ch-Ua-Mobile')}\n"
        f"SEC-F-DST     : {headers.get('Sec-Fetch-Dest')}\n"
        f"SEC-F-USER    : {headers.get('Sec-Fetch-User')}\n"
        f"SEC-F-MODE    : {headers.get('Sec-Fetch-Mode')}\n"
        f"SEC-F-SITE    : {headers.get('Sec-Fetch-Site')}\n"
        f"X-FORWARDED   : {headers.get('X-Forwarded-For')}\n"
        f"X-REAL-IP     : {headers.get('X-Real-IP')}\n"
        f"USER EMAIL    : {email}\n"
        f"PAYLOAD       : {payload}\n"
        f"{'-'*50}\n"
    )

    attack_logger.warning(alert_msg)
    send_discord_alert(alert_msg)
    send_email_alert("🚨 SQL Injection Detected", alert_msg)
