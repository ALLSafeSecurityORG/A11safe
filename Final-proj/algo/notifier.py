# notifier.py
import smtplib
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
import os

# Load sensitive data from environment variables
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "email_id")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "password_of_email_senders")
RECEIVER_EMAILS = os.getenv("RECEIVER_EMAILS", "emails_seprated_by_commas eg. email1,email2").split(",")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "web_hook_link_here")
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

def send_email(subject, body):
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = ", ".join(RECEIVER_EMAILS)
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, EMAIL_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAILS, msg.as_string())
        server.quit()
        print(f"[+] Email sent to: {', '.join(RECEIVER_EMAILS)}")
    except Exception as e:
        print(f"[!] Email error: {e}")

def send_discord_notification(message):
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json={"content": message})
        if response.status_code == 204:
            print("[+] Discord notification sent!")
        else:
            print(f"[!] Discord error: {response.status_code}")
    except Exception as e:
        print(f"[!] Discord notification error: {e}")

def send_alert(alert_type, details):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    message = f"[{alert_type.upper()} DETECTED] at {timestamp}\n\n{details}"
    
    send_email(f"{alert_type.upper()} Attack Detected", message)
    send_discord_notification(message)
