import re
import os
import logging
import requests
import smtplib
from flask import request
from datetime import datetime
from threading import Thread
from email.mime.text import MIMEText
import magic 
import ipaddress

# ============================
# Email & Discord alert settings
# ============================
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "allsafeallsafe612@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "htsneaayrqwutldg")
RECEIVER_EMAILS = os.getenv("RECEIVER_EMAILS", "unknownzero51@gmail.com,aryanbhandari2431@gmail.com").split(",")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/1371581428738953366/D1dZ3MWbVApZaeW3gJvNsH3pH1kO_m7jM1C0ypk6u-Ou8SPUiP8rvVqeESexoesleuHW")

# ============================
# Logging setup
# ============================
attack_logger = logging.getLogger("attack_logger")
attack_logger.setLevel(logging.INFO)
attack_handler = logging.FileHandler("logs/attacks.log")
attack_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
if not any(isinstance(h, logging.FileHandler) and h.baseFilename == attack_handler.baseFilename for h in attack_logger.handlers):
    attack_logger.addHandler(attack_handler)

# ============================
# Trusted proxies like Cloudflare
# ============================
TRUSTED_PROXIES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"
]

# ============================
# Utility functions
# ============================
def is_trusted_proxy(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in TRUSTED_PROXIES:
            if ip_obj in ipaddress.ip_network(net):
                return True
    except ValueError:
        return False
    return False

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

def get_geo_location(ip):
    try:
        res = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
        data = res.json()
        print(f"[DEBUG] Geolocation response for {ip}: {data}")  # Add this line for debugging
        return f"{data.get('city', 'Unknown')}, {data.get('country_name', 'Unknown')}"
    except Exception as e:
        print(f"[ERROR] Geo lookup failed for {ip}: {e}")
        return "GeoLookup Failed"

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
# Malicious Upload Detection
# ============================
def detect_malicious_upload(filename, content_type, user_info):
    ip = get_real_ip()
    geo = get_geo_location(ip)
    alerts = []

    # Checks for bad patterns
    if re.search(r"\.(php|asp|aspx|jsp|exe|sh|py|rb|pl|cgi|html?|js)(\s|$)", filename, re.IGNORECASE):
        alerts.append("🚨 Dangerous extension")
    if re.search(r"\.(jpg|jpeg|png|gif)\.(php|html?|exe|js)$", filename, re.IGNORECASE):
        alerts.append("⚠️ Double extension")
    if re.search(r"\.(php|html?|exe|js)\.(jpg|jpeg|png|gif)$", filename, re.IGNORECASE):
      alerts.append("🚨 Dangerous extension before image extension (obfuscation)")
    if re.search(r"\.(jpg|jpeg|png|gif)\.[a-z0-9]{1,6}\.(php|html?|exe|js)$", filename, re.IGNORECASE):
        alerts.append("⚠️ Triple extension")
    if re.search(r"%00", filename, re.IGNORECASE):
        alerts.append("🚨 Null byte injection attempt")
    if re.search(r"(?:\x00|\s|%00|\\x00|\/|\\)+", filename, re.IGNORECASE):
        alerts.append("⚠️ Filename obfuscation")
    # ✅ Enhanced MIME check using python-magic
    try:
        magic_mime = magic.Magic(mime=True)
        temp_file_path = os.path.join("temp", filename)
        if os.path.exists(temp_file_path):
            real_mime = magic_mime.from_file(temp_file_path)
            if not real_mime.startswith("image/"):
                alerts.append(f"🚨 MIME spoofing (actual: {real_mime})")
    except Exception as e:
        alerts.append(f"⚠️ MIME check failed: {e}")

    # If you still want to check browser-supplied MIME:
    if not content_type.startswith("image/"):
        alerts.append("⚠️ MIME spoofing (browser header)")


    if alerts:
        headers = dict(request.headers)
        method = request.method
        url = request.url
        proxy_ip = request.headers.get("X-Forwarded-For", "N/A")
        real_ip = ip

        alert_msg = (
            f"[⚠️ File Upload Detection]\n"
            f"IP: {ip} | Geo: {geo}\n"
            f"User: {user_info.get('name')} | Email: {user_info.get('email')}\n"
            f"Filename: {filename} | MIME Type: {content_type}\n"
            f"Issues: {', '.join(alerts)}\n"
            f"{'-'*50}\n"
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
            f"{'-'*50}\n"
        )

        # Log to file
        attack_logger.warning(alert_msg)

        # Notify via Discord and Email
        send_discord_alert(alert_msg)
        send_email_alert("🚨 Suspicious File Upload Detected", alert_msg)

        return True

    return False  # No issues found
