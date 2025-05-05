# utils/storage.py

import os

BASE_STORAGE_DIR = os.path.join(os.path.dirname(__file__), '../honeypot_storage')

def create_user_storage(username):
    """Creates a dedicated storage directory for a given user."""
    user_dir = os.path.join(BASE_STORAGE_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    return user_dir
