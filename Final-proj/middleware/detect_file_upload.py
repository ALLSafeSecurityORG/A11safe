import os
import logging

# Logging setup
ATTACK_LOG = "logs/attacks.log"
logging.basicConfig(filename=ATTACK_LOG, level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

ALLOWED_EXTENSIONS = [".txt"]

def is_allowed_file(filename):
    _, ext = os.path.splitext(filename)
    return ext.lower() in ALLOWED_EXTENSIONS

def detect_file_upload(file_path):
    if not is_allowed_file(file_path):
        logging.warning(f"Disallowed file upload attempt: {file_path}")
        print(f"[!] Disallowed file type: {file_path}")
        return False
    return True
