from flask import Flask, request
from werkzeug.middleware.proxy_fix import ProxyFix  # ✅ Added

from algo.routes import routes  # Import Blueprint
from middleware.detect_lfi import detect_lfi  # Import LFI detection
from algo.ip_lookup import ip_lookup_bp
from algo.ssh_console import ssh_bp  # ✅ Import the SSH Console Blueprint

# Initialize Flask app
app = Flask(__name__)
app.secret_key = "your_secret_key"  # Needed for session management

# ✅ Add ProxyFix middleware to trust real IPs from headers
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=2, x_host=1)

# Register LFI detection middleware
@app.before_request
def before_request():
    detect_lfi()

# Register Blueprints
app.register_blueprint(routes)
app.register_blueprint(ip_lookup_bp)
app.register_blueprint(ssh_bp)  # ✅ Register SSH Console blueprint with prefix

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
