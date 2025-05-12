from flask import Blueprint, request, jsonify, session
import logging
import os
from middleware.detect_shellcode import detect_shellcode
from database_setup import get_db_connection
import re

ssh_bp = Blueprint('ssh_console', __name__)

# Setup general logger
LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), '../logs/general.log')
os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
# ✅ Create a logger specific to this blueprint
ssh_logger = logging.getLogger("ssh_logger")
ssh_logger.setLevel(logging.INFO)

ssh_handler = logging.FileHandler(LOG_FILE_PATH)
ssh_handler.setFormatter(logging.Formatter('%(asctime)s - SSH Console - %(message)s'))

ssh_logger.addHandler(ssh_handler)


STORAGE_BASE = os.path.join(os.path.dirname(__file__), '../honeypot_storage')

@ssh_bp.route('/ssh/send', methods=['POST'])
def ssh_web_command():
    data = request.get_json()
    command = data.get("command", "").strip()
    output = ""

    user_id = session.get("user_id")
    username = session.get("username", "unknown")

    if not command or not user_id:
        return jsonify({"output": ""})

    # Set up user-specific storage
    user_dir = os.path.join(STORAGE_BASE, f"user_{user_id}")
    os.makedirs(user_dir, exist_ok=True)

    logging.info(f"{username} issued: {command}")

    # Get user info from DB
    conn = get_db_connection()
    user = conn.execute("SELECT username, email FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    user_info = {
        "name": user["username"] if user else "unknown",
        "email": user["email"] if user else "unknown",
        "ip": request.remote_addr,
        "geolocation": "Unknown"  # 🔥 Optional: Hook in geolocation later
    }

    # Shellcode detection
    if detect_shellcode(command, user_info):
       pass
    try:
        if command == "exit":
            output += "logout"
        elif command == "whoami":
            output += user["username"] if user else "unknown"
        elif command == "ls":
            files = os.listdir(user_dir)
            output += "  ".join(files)
        elif command.startswith("touch "):
            filename = command.split("touch ", 1)[1]
            path = os.path.join(user_dir, filename)
            open(path, 'a').close()
            output += f"Created file {filename}"
        elif command.startswith("cat "):
            filename = command.split("cat ", 1)[1]
            path = os.path.join(user_dir, filename)
            if os.path.exists(path):
                with open(path, 'r') as f:
                    output += f.read() or "(empty)"
            else:
                output += f"cat: {filename}: No such file"
        elif command.startswith("rm "):
            filename = command.split("rm ", 1)[1]
            path = os.path.join(user_dir, filename)
            if os.path.exists(path):
                os.remove(path)
                output += f"Removed {filename}"
            else:
                output += f"rm: {filename}: No such file"

        elif command.startswith("echo "):
            if '>' in command:
               try:
                   tokens = shlex.split(command)
                   if len(tokens) >= 3 and tokens[-2] == '>':
                     text = " ".join(tokens[1:-2])
                     filename = tokens[-1]
                   else:
                # Handle echo "text" > file
                       gt_index = tokens.index('>')
                       text = " ".join(tokens[1:gt_index])
                       filename = tokens[gt_index + 1]

                   path = os.path.join(user_dir, filename)

            # Prevent directory traversal
                   if not os.path.abspath(path).startswith(os.path.abspath(user_dir)):
                        raise ValueError("Invalid filename path")

                   with open(path, 'w') as f:
                        f.write(text + "\n")

                   output += f"Wrote to {filename}"
               except Exception as e:
                    ssh_logger.warning(f"[honeypot] echo command error: {e}")
                    output += f"Wrote to {filename if 'filename' in locals() else 'file'}"
            else:
               output += "Invalid echo syntax. Use: echo \"text\" > filename"

        elif command == "clear":
            output += "clear_console"
        elif command == "help":
            output += (
                "Available commands:\n"
                "whoami, ls, cat <file>, touch <file>, rm <file>, echo \"text\" > <file>, clear, exit"
            )
        else:
            output += f"bash: {command}: command not found"
    except Exception as e:
        output += f"Error: {str(e)}"

    return jsonify({"output": output})
