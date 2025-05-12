import re
import logging
import ipaddress
import requests
import os
import smtplib
from flask import request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

# ========== LOGGER SETUP ========== #
attack_logger = logging.getLogger("html_injection_logger")
attack_logger.setLevel(logging.INFO)
attack_handler = logging.FileHandler("logs/attacks.log")
attack_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
if not any(isinstance(h, logging.FileHandler) and h.baseFilename == attack_handler.baseFilename for h in attack_logger.handlers):
    attack_logger.addHandler(attack_handler)

# ========== CONFIGURATION ========== #
GEO_API = "http://ip-api.com/json/"

SENDER_EMAIL = os.getenv("SENDER_EMAIL", "allsafeallsafe612@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "htsneaayrqwutldg")
RECEIVER_EMAILS = os.getenv("RECEIVER_EMAILS", "unknownzero51@gmail.com,aryanbhandari2431@gmail.com").split(",")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/1371581428738953366/D1dZ3MWbVApZaeW3gJvNsH3pH1kO_m7jM1C0ypk6u-Ou8SPUiP8rvVqeESexoesleuHW")

CLOUDFLARE_IP_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/12",
    "172.64.0.0/13", "131.0.72.0/22", "104.24.0.0/14"
]

SUSPICIOUS_HTML_TAGS = re.compile(r"<\s*(script|iframe|object|embed|form|img|svg|style|link)[^>]*>", re.IGNORECASE)
SUSPICIOUS_XSS = re.compile(r"(on\w+\s*=|javascript:|alert\s*\(|document\.cookie|<\s*script[^>]*>)", re.IGNORECASE)
SUSPICIOUS_PHP = re.compile(r"<\?php|<\?=|\?>", re.IGNORECASE)

# ========== ALERTING FUNCTIONS ========== #
def send_email(subject, body):
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = ", ".join(RECEIVER_EMAILS)
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, EMAIL_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAILS, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"[!] Email error: {e}")

def send_discord_notification(message):
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json={"content": message})
        if response.status_code != 204:
            print(f"[!] Discord webhook error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"[!] Discord error: {e}")

# ========== UTILITY FUNCTIONS ========== #
def is_binary_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(512)
            return b'\x00' in chunk
    except Exception:
        return True

def is_ip_in_cloudflare_range(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in CLOUDFLARE_IP_RANGES:
            if ip_obj in ipaddress.ip_network(net):
                return True
    except Exception:
        return False
    return False

def get_real_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    remote_ip = request.remote_addr or "Unknown"
    if forwarded_for:
        ip = forwarded_for.split(",")[0].strip()
        return ip if is_ip_in_cloudflare_range(remote_ip) else f"Invalid Proxy IP: {remote_ip}"
    return remote_ip

def get_geolocation(ip):
    try:
        response = requests.get(GEO_API + ip, timeout=3)
        data = response.json()
        if data.get("status") == "success":
            return f"{data['country']}, {data['regionName']}, {data['city']}, ISP: {data['isp']}"
    except Exception:
        pass
    return "Geolocation not available"

# ========== MAIN DETECTION ========== #

def detect_html_injection(file_path):
    ip = get_real_ip()
    location = get_geolocation(ip)
    now = datetime.now()
    method = request.method
    url = request.url
    user_agent = request.headers.get("User-Agent", "Unknown")
    referer = request.headers.get("Referer", "None")
    filename = os.path.basename(file_path)

    if is_binary_file(file_path):
        attack_logger.info(f"Skipped binary file: {file_path} | IP: {ip} | Location: {location}")
        return False

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        alerts = []
        if SUSPICIOUS_HTML_TAGS.search(content): alerts.append("HTML tag detected")
        if SUSPICIOUS_XSS.search(content): alerts.append("Potential XSS detected")
        if SUSPICIOUS_PHP.search(content): alerts.append("PHP code detected")

        suspicious = bool(alerts)

        # Prepare log block
        log_block = []
        log_block.append(f"[{'⚠️ ATTACK DETECTED' if suspicious else 'GENERAL NOTE SAVED'}] [{now}]")
        log_block.append(f"Filename: {filename}")
        log_block.append(f"Content Preview: {content[:100]}...")
        log_block.append("-" * 60)
        log_block.append(f"[{now}] IP: {ip} | GEO: {location} | METHOD: {method} | URL: {url} | UA: {user_agent} | REFERER: {referer}")
        log_block.append("=" * 60 + "\n")

        general_logger.info("\n".join(log_block))

        if suspicious:
            alert_summary = ', '.join(alerts)
            msg = f"[Injection Alert] File: {file_path} | Issues: {alert_summary} | IP: {ip} | Location: {location}"
            attack_logger.warning(msg)
            print(f"[!] {msg}")

            # Extra detailed attack info
            headers = request.headers
            proxy_ip = request.remote_addr or "Unknown"
            real_ip = get_real_ip()
            geo = get_geolocation(real_ip)
            now = datetime.now()
            method = request.method
            url = request.url
            source = "FILE"
            data_value = file_path

            attack_info = (
                f"[{now}] [HTML INJECTION DETECTED - {source}]\n"
                f"REAL_IP       : {real_ip}\n"
                f"PROXY_IP      : {proxy_ip}\n"
                f"GEOLOCATION   : {geo}\n"
                f"{source:<13}: {data_value}\n"
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
            attack_logger.info(attack_info)

            # Alerts
            subject = "[Locater Alert] HTML Injection Detected"
            email_msg = (
                f"⚠️ **HTML Injection Detected**\n\n"
                f"File: {file_path}\n"
                f"Issues: {alert_summary}\n"
                f"IP: {ip}\n"
                f"Location: {location}\n"
            )

            send_email(subject, email_msg)
            send_discord_notification(email_msg)

            
        return suspicious

    except Exception as e:
        attack_logger.error(f"[Error] File: {file_path} | Reason: {e} | IP: {ip} | Location: {location}")
        return False
