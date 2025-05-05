from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify, current_app, send_file
import sqlite3
import subprocess
import zipfile
from io import BytesIO
import os
from algo.hash_converter import (
    encrypt_aes, decrypt_aes,
    encrypt_base64, decrypt_base64,
    encrypt_rot13, decrypt_rot13,
    hash_md5, hash_sha1, hash_sha256
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from database_setup import get_db_connection
from middleware.detect_sql import detect_sql_injection  # 🔒 SQLi detection import
from middleware.detect_xss import detect_xss  # 🛡️ XSS detection import
from middleware.detect_ssrf import detect_ssrf  # 🌐 SSRF Detection
from middleware.content_detect import log_content
from utils.storage import create_user_storage  # 👈 import the storage helper
from middleware.detect_pic_upload import detect_malicious_upload
from database_setup import get_db_connection
from middleware.detect_html_injection import detect_html_injection
from middleware.detect_ssti import detect_ssti_from_data

routes = Blueprint("routes", __name__)

# Database Connection Helper
def get_db_connection():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row  # Access rows as dictionaries
    return conn

# Home Page
@routes.route("/")
def home():
    return render_template("login.html")

# Signup Route
@routes.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        ip = request.remote_addr

        # 🔒 SQL Injection Detection
        if detect_sql_injection(email, password, ip) or detect_sql_injection(username, "", ip):
            flash("Suspicious activity detected. Signup denied.", "danger")
            return redirect(url_for("routes.signup"))

        # 🛡️ XSS Detection
        if detect_xss(("username", username), ("email", email), ("password", password), request=request):
            flash("XSS attack detected. Signup denied.", "danger")
            return redirect(url_for("routes.signup"))
        # 🧩 SSTI Detection
        if detect_ssti_from_data(username=username, email=email, password=password):
            flash("SSTI attack detected. Signup denied.", "danger")
            return redirect(url_for("routes.signup"))
            
        # 🌐 SSRF Detection
        if detect_ssrf(email, password, ip):
            flash("SSRF attack detected. Login denied.", "danger")
            return redirect(url_for("routes.login"))

        conn = get_db_connection()
        cursor = conn.cursor()

        # 🚫 Check for duplicate email or username
        cursor.execute("SELECT id FROM users WHERE email = ? OR username = ?", (email, username))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Username or Email already exists. Please try another.", "warning")
            conn.close()
            return redirect(url_for("routes.signup"))

        # ✅ Continue if all checks passed
        hashed_password = generate_password_hash(password)

        try:
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
                           (username, email, hashed_password))
            conn.commit()

            # 🎯 Create user-specific honeypot storage directory
            create_user_storage(username)

            flash("Signup successful! You can now log in.", "success")
            return redirect(url_for("routes.login"))
        except sqlite3.Error as e:
            flash("Something went wrong. Please try again later.", "danger")
        finally:
            conn.close()

    return render_template("login.html")


# Login Route
@routes.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        ip = request.remote_addr

        # 🔒 SQL Injection Detection
        if detect_sql_injection(email, password, ip):
            flash("Suspicious activity detected. Login denied.", "danger")
            return redirect(url_for("routes.login"))

        # 🛡️ XSS Detection
        if detect_xss(("email", email), ("password", password), ip=ip):
            flash("XSS attack detected. Login denied.", "danger")
            return redirect(url_for("routes.login"))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Login successful!", "success")
            return redirect(url_for("routes.dashboard"))  # Redirect to dashboard.html
        else:
            flash("Invalid credentials. Please try again.", "danger")

    return render_template("login.html")



# Dashboard Route
@routes.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("You need to log in first!", "warning")
        return redirect(url_for("routes.login"))

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, linkedin, profile_pic FROM users")
    users = cursor.fetchall()
    conn.close()

    return render_template("dashboard.html", username=session["username"], users=users)

# IP Lookup Route
@routes.route("/ip_lookup")
def ip_lookup():
    if "user_id" not in session:
        flash("You need to log in first!", "warning")
        return redirect(url_for("routes.login"))

    return render_template("ip_lookup.html")

# Logout Route
@routes.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully!", "info")
    return redirect(url_for("routes.login"))

# Notepad Route
@routes.route("/note_pad")
def note_pad():
    if "user_id" not in session:
        flash("You need to log in first!", "warning")
        return redirect(url_for("routes.login"))
    
    return render_template("note_pad.html")

# SSH Console Route
@routes.route("/ssh_console")
def ssh_console():
    if "user_id" not in session:
        flash("You need to log in first!", "warning")
        return redirect(url_for("routes.login"))
    
    return render_template("ssh_console.html")


    # Encryption & Decryption Route
@routes.route('/hash_converter', methods=['GET', 'POST'])
def hash_converter_page():
    encrypted_text = decrypted_text = None
    if request.method == 'POST':
        method = request.form.get('method')
        text = request.form.get('text')
        key = request.form.get('key')  # AES needs this
        action = request.form.get('action')
        ip = request.remote_addr or "unknown"

        # ✅ Check for XSS in all fields
        detect_xss(("text", text), ("key", key), ip=ip)
        
        try:
            if action == 'encrypt':
                if method == 'aes':
                  if not key:
                    encrypted_text = "Error: AES key required."
                  else:
                    encrypted_text = encrypt_aes(text, key)
                elif method == 'base64':
                    encrypted_text = encrypt_base64(text)
                elif method == 'rot13':
                    encrypted_text = encrypt_rot13(text)
                elif method == 'md5':
                    encrypted_text = hash_md5(text)
                elif method == 'sha1':
                    encrypted_text = hash_sha1(text)
                elif method == 'sha256':
                    encrypted_text = hash_sha256(text)
                elif method == 'rsa':
                     if not key:
                        encrypted_text = "Error: RSA public key required."
                     else:
                        encrypted_text = rsa_encrypt(text, key)
                else:
                    encrypted_text = 'Unsupported encryption method.'
            elif action == 'decrypt':
                if method == 'aes':
                    if not key:
                      decrypted_text = "Error: AES key required."
                    else:
                      decrypted_text = decrypt_aes(text, key)
                elif method == 'base64':
                    decrypted_text = decrypt_base64(text)
                elif method == 'rot13':
                    decrypted_text = decrypt_rot13(text)
                elif method == 'rsa':
                   if not key:
                      decrypted_text = "Error: RSA private key required."
                   else:
                      decrypted_text = rsa_decrypt(text, key)         
                else:
                    decrypted_text = 'Unsupported decryption method.'
        except Exception as e:
            decrypted_text = encrypted_text = f"Error: {str(e)}"

    return render_template('hash_converter.html', encrypted_text=encrypted_text, decrypted_text=decrypted_text)

 # profile   

UPLOAD_FOLDER = "static/profile_pics"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

@routes.before_app_request
def setup_upload_folder():
    current_app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@routes.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        flash("You need to log in first!", "warning")
        return redirect(url_for("routes.login"))

    user_id = session["user_id"]
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if request.method == "POST":
        ip = request.remote_addr or "Unknown"

        # Update profile picture
        if "profile_pic" in request.files:
            file = request.files["profile_pic"]
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)

                # Save temporarily for scanning
                temp_path = os.path.join("temp", filename)
                os.makedirs("temp", exist_ok=True)
                file.save(temp_path)

                # Log content for suspicious HTML/JS/PHP
                with open(temp_path, "r", errors="ignore") as f:
                    content = f.read()
                    log_content(content, filename)
                    if detect_html_injection(temp_path):
                        flash("Malicious content detected in image!", "danger")
                        os.remove(temp_path)
                        return redirect(url_for("routes.profile"))

                # Move to permanent user folder
                user_folder = os.path.join(current_app.config["UPLOAD_FOLDER"], f"user_{user_id}")
                os.makedirs(user_folder, exist_ok=True)
                final_path = os.path.join(user_folder, filename)
                os.replace(temp_path, final_path)

                relative_path = f"user_{user_id}/{filename}"
                conn.execute("UPDATE users SET profile_pic = ? WHERE id = ?", (relative_path, user_id))
                conn.commit()
                flash("Profile picture updated successfully!", "success")

        # Update social media links and description
        facebook = request.form.get("facebook", "")
        twitter = request.form.get("twitter", "")
        linkedin = request.form.get("linkedin", "")
        description = request.form.get("description", "")

        # Detect XSS & SSRF in all fields
        if detect_xss(
            ("facebook", facebook),
            ("twitter", twitter),
            ("linkedin", linkedin),
            ("description", description),
            ip=ip
        ):
            flash("Potential XSS attack detected in input!", "danger")
            return redirect(url_for("routes.profile"))

        if detect_ssrf(facebook, twitter, linkedin, ip):
            flash("SSRF pattern detected in input!", "danger")
            return redirect(url_for("routes.profile"))

        conn.execute(
            "UPDATE users SET facebook = ?, twitter = ?, linkedin = ?, description = ? WHERE id = ?",
            (facebook, twitter, linkedin, description, user_id),
        )
        conn.commit()
        flash("Profile updated successfully!", "success")

    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    return render_template("profile.html", user=user)
# update profile pic 
@routes.route("/update_profile_pic", methods=["POST"])
def update_profile_pic():
    if "user_id" not in session:
        flash("You need to log in first!", "warning")
        return redirect(url_for("routes.login"))

    file = request.files.get("profile_pic")
    if not file or file.filename == "":
        flash("No file selected!", "danger")
        return redirect(url_for("routes.profile"))

    filename = secure_filename(file.filename)
    content_type = file.content_type

    # DB connection + user info
    conn = get_db_connection()
    user_id = session["user_id"]
    user = conn.execute("SELECT name, email FROM users WHERE id = ?", (user_id,)).fetchone()
    user_info = {"name": user["name"], "email": user["email"]}

    # ✅ Detect malicious uploads
    if detect_malicious_upload(filename, content_type, user_info):
        flash("⚠️ Malicious upload attempt detected! Logged.", "danger")
        conn.close()
        return redirect(url_for("routes.profile"))

    # ✅ Sanity check for allowed image types
    if not filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
        flash("❌ Invalid image type!", "danger")
        conn.close()
        return redirect(url_for("routes.profile"))

    # ✅ Save profile picture
    upload_dir = os.path.join("static", "profile_pics", f"user_{user_id}")
    os.makedirs(upload_dir, exist_ok=True)
    filepath = os.path.join(upload_dir, filename)
    file.save(filepath)

    # ✅ Save relative path to DB
    relative_path = os.path.relpath(filepath, "static")
    conn.execute("UPDATE users SET profile_pic = ? WHERE id = ?", (relative_path, user_id))
    conn.commit()
    conn.close()

    flash("✅ Profile picture updated!", "success")
    return redirect(url_for("routes.profile"))
# save notes
@routes.route('/save_note', methods=['POST'])
def save_note():
    data = request.get_json()
    content = data.get('content')
    filename = data.get('filename')

    if not content or not filename:
        return jsonify({"status": "error", "message": "Missing content or filename"}), 400

    log_content(content, filename)
    return jsonify({"status": "success", "message": "Note saved and logged."})

@routes.route("/rsa_keys", methods=["GET", "POST"])
def manage_rsa_keys():
    if "user_id" not in session:
        flash("You need to log in first!", "warning")
        return redirect(url_for("routes.login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == "POST":
        public_key = request.form.get("public_key")
        private_key = request.form.get("private_key")

        cursor.execute(
            "INSERT INTO rsa_keys (user_id, public_key, private_key) VALUES (?, ?, ?)",
            (session["user_id"], public_key, private_key)
        )
        conn.commit()
        flash("RSA keys added successfully!", "success")

    cursor.execute("SELECT * FROM rsa_keys WHERE user_id = ?", (session["user_id"],))
    keys = cursor.fetchall()
    conn.close()

    return render_template("rsa_keys.html", keys=keys)


# admin login
@routes.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")  # Use .get() for safety
        password = request.form.get("password")

        if username == "admin" and password == "SuperSecure@123":
            session["admin_logged_in"] = True  # ✅ MATCHES what panel checks
            flash("Welcome, Admin!", "success")
            return redirect(url_for("routes.admin_panel"))
        else:
            flash("Invalid admin credentials!", "danger")

    return render_template("admin_login.html")


# admin_panel
@routes.route("/admin_panel")
def admin_panel():
    if "admin_logged_in" not in session:
        flash("Admin access required!", "danger")
        return redirect(url_for("routes.admin_login"))

    try:
        with open("logs/general.log", "r") as f:
            general_logs = f.readlines()
    except FileNotFoundError:
        general_logs = ["[!] general.log not found"]

    try:
        with open("logs/attacks.log", "r") as f:
            attack_logs = f.readlines()
    except FileNotFoundError:
        attack_logs = ["[!] attacks.log not found"]

    return render_template("admin_panel.html", general_logs=general_logs, attack_logs=attack_logs)

  # exportlogs

@routes.route('/download-logs')
def download_logs():
    log_folder = os.path.join(os.getcwd(), 'logs')  # Full path to the logs folder
    files_to_zip = ['attacks.log', 'general.log']
    
    # Create an in-memory ZIP archive
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
        for filename in files_to_zip:
            filepath = os.path.join(log_folder, filename)
            if os.path.exists(filepath):
                zip_file.write(filepath, arcname=filename)

    zip_buffer.seek(0)

    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name='logs.zip'
    )


@routes.route('/refresh_logs')
def refresh_logs():
    try:
        with open('logs/general.log', 'r') as g:
            general_logs = g.read()
        with open('logs/attacks.log', 'r') as a:
            attack_logs = a.read()
        return jsonify({
            'general_logs': general_logs,
            'attack_logs': attack_logs
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
