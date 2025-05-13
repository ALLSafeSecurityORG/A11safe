import re
import os
import requests
from datetime import datetime
from flask import request
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import ipaddress

ATTACK_LOG = 'logs/attacks.log'
GENERAL_LOG = 'logs/general.log'

# Email & Discord alert settings
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "allsafeallsafe612@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "htsneaayrqwutldg")
RECEIVER_EMAILS = os.getenv("RECEIVER_EMAILS", "unknownzero51@gmail.com,aryanbhandari2431@gmail.com").split(",")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/1367935673419694290/ZsrM2jsXscoda4GrJoPNYRNScJkW8tfa_FmlW5lfEp86VR4n_-AoDtbsRNizvaerRDvN")

# Trusted proxies like Cloudflare
TRUSTED_PROXIES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # IPv6 ranges
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]

# Patterns to detect common attack content (basic XSS for now)
suspicious_patterns = [
    # 🔥 XSS & HTML-based
    r"<script.*?>.*?</script>",
    r"on\w+\s*=",
    r"javascript:",
    r"<iframe.*?>",
    r"<img\s+.*?onerror\s*=.*?>",
    r"document\.cookie",
    r"alert\s*\(",
    r"window\.location",
    r"<svg.*?onload\s*=.*?>",
    
    # 🔥 Basic Command Injection
    r";\s*[\w\-\.\/]+",
    r"\|\|",
    r"\&\&",
    r"\$\(",
    r"`.*?`",
    r"\b(cat|ls|whoami|id|uname|pwd|ifconfig)\b",
    r"\bping\s+-c\s+\d+\s+\d{1,3}(?:\.\d{1,3}){3}",
    
    # 🔥 Reverse Shells - Bash
    r"bash\s+-i\s+>&\s+/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+\s+0>&1",
    r"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+",
    r"/bin/bash\s+-i",
    r"exec\s+5<>/dev/tcp",

    # 🔥 Reverse Shells - Netcat / ncat
    r"nc\s+-e\s+/bin/sh\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+",
    r"ncat\s+-e\s+/bin/bash",
    r"nc.traditional\s+-e",
    r"nc\s+-nv",
    
    # 🔥 Python Shells
    r"python\s+-c\s+.*?socket\.socket",
    r"import\s+socket.*?connect\(",
    r"os\.dup2",

    # 🔥 Perl / PHP / Ruby
    r"perl\s+-e\s+.*?IO::Socket::INET",
    r"php\s+-r\s+.*?fsockopen",
    r"\$sock\s*=\s*fsockopen",
    r"ruby\s+-rsocket\s+-e\s+.*?TCPSocket",

    # 🔥 PowerShell
    r"powershell\s+-nop.*?Net\.Sockets\.TCPClient",
    r"IEX\s*\(",
    r"Invoke-Expression",
    r"DownloadString",

    # 🔥 Wget / Curl Abuse
    r"wget\s+.*?;\s+chmod\s+\+x\s+.*?;\s+.*?\.\/.*?",
    r"curl\s+.*?;\s+chmod\s+\+x\s+.*?;\s+.*?\.\/.*?",
    r"(curl|wget)\s+.*?\|\s*sh",

    # 🔥 File Upload Exploits
    r"\.php[3457]?",
    r"\.jsp",
    r"\.asp[x]?",
    r"\.exe",
    r"\.bat",
    r"\.sh",
    r"\.py",
    r"\.pl",

    # 🔥 Base64 / Hex Encoding
    r"echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+-d\s*\|\s*sh",
    r"base64\s+-d\s+.*?\|\s+sh",
    r"[A-Fa-f0-9]{40,}",

    # 🔥 Local File Inclusion / Path Traversal
    r"\.\./\.\./",
    r"etc/passwd",
    r"proc/self/environ",
    r"/var/log/",
    r"input_file=.*?passwd",

    # 🔥 Remote File Inclusion / RCE
    r"https?://.*?\.(php|txt|sh)",
    r"eval\s*\(",
    r"system\s*\(",
    r"exec\s*\(",
    r"shell_exec\s*\(",
    r"passthru\s*\(",
    r"popen\s*\(",
    r"proc_open\s*\(",

    # 🔥 Windows LOLBAS / Command Execution
    r"cmd\.exe",
    r"powershell\.exe",
    r"rundll32",
    r"regsvr32",
    r"certutil\s+-urlcache",
    r"bitsadmin",
    r"mshta\s+",

    # 🔥 Container Escape / Docker
    r"docker\s+run",
    r"mount\s+-t\s+proc",
    r"chroot\s+/mnt",
    r"/root/.ssh",
    r"/bin/bash\s+\d{1,3}(?:\.\d{1,3}){3}",

]



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
        print(f"[!] Email alert error: {e}")

def send_discord_notification(message):
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json={"content": message})
        if response.status_code != 204:
            print(f"[!] Discord webhook error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"[!] Discord webhook error: {e}")

def is_suspicious_content(content):
    for pattern in suspicious_patterns:
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            return True
    return False


def get_real_ip():
    """Return the actual client IP address by validating trusted proxies."""
    x_forwarded_for = request.headers.get("X-Forwarded-For", "")
    ip_list = [ip.strip() for ip in x_forwarded_for.split(",") if ip.strip()]

    # If there are no proxies in the chain, use the direct remote address
    if not ip_list:
        return request.remote_addr

    # Reverse the list to check from closest to client to furthest (last is client IP)
    for ip in reversed(ip_list):
        if not is_trusted_proxy(ip):
            return ip

    # If all IPs in the X-Forwarded-For chain are trusted proxies, return the last IP
    return ip_list[-1] if ip_list else request.remote_addr

def is_trusted_proxy(ip):
    """Check if the IP is in the list of trusted proxy ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in TRUSTED_PROXIES:
            if ip_obj in ipaddress.ip_network(cidr):
                return True
    except ValueError:
        pass
    return False

def get_geo_info(ip):
    """Fetch geolocation data using a public API."""
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3)
        if response.status_code == 200:
            data = response.json()
            country = data.get("country_name", "Unknown")
            region = data.get("region", "Unknown")
            city = data.get("city", "Unknown")
            org = data.get("org", "Unknown")
            return f"{city}, {region}, {country} | ISP: {org}"
        else:
            return "Geolocation API error"
    except Exception as e:
        return f"Geolocation failed: {e}"

def log_content(content, filename):
    now = datetime.now()
    real_ip = get_real_ip()
    proxy_ip = request.remote_addr or "Unknown"
    geo = get_geo_info(real_ip)
    
    user_agent = request.headers.get("User-Agent", "Unknown")
    referer = request.headers.get("Referer", "Unknown")
    method = request.method
    url = request.url
    headers = request.headers
    extension = os.path.splitext(filename)[-1].lower()
    suspicious_filetype = extension in ['.php', '.html', '.js']
    suspicious_filename = bool(re.search(r"<script.*?>|javascript:|alert\s*\(", filename, re.IGNORECASE))
    suspicious = is_suspicious_content(content) or suspicious_filetype or suspicious_filename
    log_path = ATTACK_LOG if suspicious else GENERAL_LOG

    log_header = "[⚠️ ATTACK DETECTED]" if suspicious else "[GENERAL NOTE SAVED]"
    
    log_lines = [
        f"{log_header} [{now}]",
        f"Filename: {filename}",
        f"Content Preview: {content[:100]}...",
        "-" * 60,
        f"REAL_IP       : {real_ip}",
        f"PROXY_IP      : {proxy_ip}",
        f"GEOLOCATION   : {geo}",
        f"FILENAME      : {filename}",
        f"METHOD        : {method}",
        f"URL           : {url}",
        f"USER-AGENT    : {headers.get('User-Agent')}",
        f"REFERRER      : {request.referrer}",
        f"HOST          : {headers.get('Host')}",
        f"ORIGIN        : {headers.get('Origin')}",
        f"COOKIE        : {headers.get('Cookie')}",
        f"ACCEPT        : {headers.get('Accept')}",
        f"ACCEPT-LANG   : {headers.get('Accept-Language')}",
        f"ACCEPT-ENC    : {headers.get('Accept-Encoding')}",
        f"CONTENT-TYPE  : {headers.get('Content-Type')}",
        f"CONTENT-LEN   : {headers.get('Content-Length')}",
        f"CONNECTION    : {headers.get('Connection')}",
        f"CACHE-CONTROL : {headers.get('Cache-Control')}",
        f"SEC-GPC       : {headers.get('Sec-GPC')}",
        f"SEC-UA        : {headers.get('Sec-Ch-Ua')}",
        f"SEC-UA-PLAT   : {headers.get('Sec-Ch-Ua-Platform')}",
        f"SEC-UA-MOB    : {headers.get('Sec-Ch-Ua-Mobile')}",
        f"SEC-F-DST     : {headers.get('Sec-Fetch-Dest')}",
        f"SEC-F-USER    : {headers.get('Sec-Fetch-User')}",
        f"SEC-F-MODE    : {headers.get('Sec-Fetch-Mode')}",
        f"SEC-F-SITE    : {headers.get('Sec-Fetch-Site')}",
        f"X-FORWARDED   : {headers.get('X-Forwarded-For')}",
        f"X-REAL-IP     : {headers.get('X-Real-IP')}",
        "-" * 50,
        "=" * 60,
        ""
    ]

    with open(log_path, 'a') as f:
        f.write("\n".join(log_lines))

    # Send alerts if suspicious
    if suspicious:
        subject = "[Locater Alert] Suspicious Content Detected"
        message = "\n".join([
            "⚠️ **Suspicious Content Detected**",
            f"Time: {now}",
            f"REAL_IP       : {real_ip}",
            f"PROXY_IP      : {proxy_ip}",
            f"GEOLOCATION   : {geo}",
            f"FILENAME      : {filename}",
            f"METHOD        : {method}",
            f"URL           : {url}",
            f"USER-AGENT    : {headers.get('User-Agent')}",
            f"REFERRER      : {request.referrer}",
            f"HOST          : {headers.get('Host')}",
            f"ORIGIN        : {headers.get('Origin')}",
            f"COOKIE        : {headers.get('Cookie')}",
            f"ACCEPT        : {headers.get('Accept')}",
            f"ACCEPT-LANG   : {headers.get('Accept-Language')}",
            f"ACCEPT-ENC    : {headers.get('Accept-Encoding')}",
            f"CONTENT-TYPE  : {headers.get('Content-Type')}",
            f"CONTENT-LEN   : {headers.get('Content-Length')}",
            f"CONNECTION    : {headers.get('Connection')}",
            f"CACHE-CONTROL : {headers.get('Cache-Control')}",
            f"SEC-GPC       : {headers.get('Sec-GPC')}",
            f"SEC-UA        : {headers.get('Sec-Ch-Ua')}",
            f"SEC-UA-PLAT   : {headers.get('Sec-Ch-Ua-Platform')}",
            f"SEC-UA-MOB    : {headers.get('Sec-Ch-Ua-Mobile')}",
            f"SEC-F-DST     : {headers.get('Sec-Fetch-Dest')}",
            f"SEC-F-USER    : {headers.get('Sec-Fetch-User')}",
            f"SEC-F-MODE    : {headers.get('Sec-Fetch-Mode')}",
            f"SEC-F-SITE    : {headers.get('Sec-Fetch-Site')}",
            f"X-FORWARDED   : {headers.get('X-Forwarded-For')}",
            f"X-REAL-IP     : {headers.get('X-Real-IP')}",
            f"Content Preview: {content[:100]}..."
        ])
        send_discord_notification(message)
        send_email(subject, message)
