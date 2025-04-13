from flask import Flask, render_template, request, redirect, url_for, session, abort
import os, subprocess, time
from threading import Thread
from wakeonlan import send_magic_packet
from datetime import timedelta
import hmac
import platform
import hashlib
import json

app = Flask(__name__)
# app.config['SESSION_COOKIE_DOMAIN'] = '.kucniserver.duckdns.org' 
app.secret_key = 'sda8@k!82nasd8r1sad129u1asdu1@##!' # kljuc sesije
app.permanent_session_lifetime = timedelta(days=30)  # sesija traje 30 dana

# Github
GITHUB_SECRET = b'a9S$8@x!kLm#2Z7rPq*3VgBz'  # ✅ bytes

# Login podaci
USERNAME = "KucniAdmin" # test again
PASSWORD = "sara-2021"

# Glavni server
SERVER_IP = "192.168.0.50"
SERVER_MAC = "04:d4:c4:f2:a0:15"

def get_usage_data():
    try:
        output = subprocess.check_output(
            ["/mnt/Main_data/scripts/server_web_fallback/commands/get_usage.sh"]
        ).decode()
        return json.loads(output)
    except Exception as e:
        print(f"Usage error: {e}")
        return {}

def get_traffic_data():
    try:
        output = subprocess.check_output(
            ["/mnt/Main_data/scripts/server_web_fallback/commands/get_traffic.sh"]
        ).decode()
        return json.loads(output)
    except Exception as e:
        print(f"Traffic error: {e}")
        return {}

def get_login_stats():
    try:
        output = subprocess.check_output(
            ["/mnt/Main_data/scripts/server_web_fallback/commands/get_login_stats.sh"]
        ).decode()
        return json.loads(output)
    except Exception as e:
        print(f"Login stats error: {e}")
        return {}

@app.route('/shutdown', methods=['POST'])
def shutdown():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    try:
        subprocess.check_call(["/mnt/Main_data/scripts/server_web_fallback/commands/shutdown.sh"])
        return "OK", 200
    except:
        return "Failed to shutdown", 500

@app.route('/restart', methods=['POST'])
def restart():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    try:
        subprocess.check_call(["/mnt/Main_data/scripts/server_web_fallback/commands/restart.sh"])
        return "OK", 200
    except:
        return "Failed to restart", 500


@app.route('/', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        success = (username == USERNAME and password == PASSWORD)

        # Loguj pokušaj
        log_type = "success" if success else "fail"
        log_path = "/mnt/Main_data/scripts/server_web_fallback/logs/login.log"
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        with open(log_path, "a") as f:
            f.write(f"{log_type}|{int(time.time())}\n")

        if success:
            session.permanent = True
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        return render_template('login.html', error="Wrong login.")

    return render_template('login.html')


@app.before_request
def set_cookie_domain_and_auth():
    # Ako domen NIJE localhost → postavi domen kolačića
    if not request.host.startswith("localhost") and not request.host.startswith("127.0.0.1"):
        app.config['SESSION_COOKIE_DOMAIN'] = ".kucniserver.duckdns.org"
    else:
        app.config['SESSION_COOKIE_DOMAIN'] = None

    # Dozvoli GitHub webhook bez login-a
    if request.path == '/github_deploy':
        return

    # Sve ostalo traži login
    if not session.get('logged_in') and request.endpoint not in ['login', 'static']:
        return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    try:
        if platform.system().lower() == "windows":
            # Windows ping
            online = subprocess.call(['ping', '-n', '1', SERVER_IP], stdout=subprocess.DEVNULL) == 0
        else:
            # Linux ping
            online = subprocess.call(['ping', '-c', '1', '-W', '1', SERVER_IP], stdout=subprocess.DEVNULL) == 0
    except Exception:
        online = False

    services = get_service_statuses() if online else {}
    usage = get_usage_data() if online else {}
    traffic = get_traffic_data() if online else {}
    logins = get_login_stats()

    return render_template(
    "dashboard.html",
    online=online,
    services=services,
    usage=usage,
    traffic=traffic,
    logins=logins
)


@app.route('/wakeup', methods=['POST'])
def wakeup():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    send_magic_packet(SERVER_MAC)
    time.sleep(5)
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/auth_check')
def auth_check():
    if not session.get('logged_in'):
        return "Unauthorized", 401
    return "OK", 200

@app.route('/apps')
def apps():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if platform.system().lower() == "windows":
        server_online = subprocess.call(['ping', '-n', '1', SERVER_IP], stdout=subprocess.DEVNULL) == 0
    else:
        server_online = subprocess.call(['ping', '-c', '1', '-W', '1', SERVER_IP], stdout=subprocess.DEVNULL) == 0

    # Lokalna mreža → koristi IP adresu
    if request.host.startswith("192.168."):
        base = "http://192.168.0.50"
    else:
        base = "https://"

    apps = {
        "Radarr": f"{base}radarr.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:30025",
        "Sonarr": f"{base}sonarr.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:30113",
        "Overseerr": f"{base}overseerr.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:30002",
        "Bazarr": f"{base}bazarr.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:30046",
        "Prowlarr": f"{base}prowlarr.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:30050",
        "Photoprism": f"{base}slike.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:20800",
        "Pi-hole": f"{base}pihole.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:20720/admin",
        "qbittorrent": f"{base}torrent.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:30024",
        "Portainer": f"{base}portainer.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:31015",
        "Syncthing": f"{base}sync.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:20910"
    }

    return render_template("apps.html", online=server_online, apps=apps)

@app.route('/github_deploy', methods=['POST'])
def github_deploy():
    signature = request.headers.get('X-Hub-Signature-256')
    if signature is None:
        abort(400, "Missing signature")

    sha_name, signature = signature.split('=')
    if sha_name != 'sha256':
        abort(400, "Invalid signature format")

    payload_raw = request.get_data()
    mac = hmac.new(GITHUB_SECRET, msg=payload_raw, digestmod=hashlib.sha256)

    if not hmac.compare_digest(mac.hexdigest(), signature):
        abort(403, "Invalid signature")

    # Parse payload JSON
    payload = json.loads(payload_raw)

    # Provera da li je push bio na main granu
    if payload.get("ref") != "refs/heads/main":
        return "Not main branch – deploy skipped.", 200

    # Pokreni deploy skriptu u pozadini
    def background_task():
        subprocess.call(["/mnt/Main_data/scripts/server_web_fallback/deploy.sh"])

    Thread(target=background_task).start()
    return "Deploy triggered on main", 200

def get_service_statuses():
    try:
        output = subprocess.check_output(
            ["/mnt/Main_data/scripts/server_web_fallback/commands/service_status.sh"]
        ).decode().strip().splitlines()
        services = {}
        for line in output:
            if ':' in line:
                name, status = line.split(':', 1)
                services[name.strip()] = status.strip()
        return services
    except Exception:
        return {}

@app.route("/service/<name>/<action>", methods=["POST"])
def manage_service(name, action):
    allowed_actions = ["start", "stop", "restart"]
    if action not in allowed_actions:
        return "Invalid action", 400

    try:
        subprocess.check_call([
            "/mnt/Main_data/scripts/server_web_fallback/commands/manage_service.sh",
            name,
            action
        ])
        return "OK", 200
    except subprocess.CalledProcessError:
        return "Failed to execute", 500


if __name__ == "__main__":
    print("🔗 Pristupi aplikaciji na:", os.getenv("LOCAL_URL", "http://localhost:8899"))
    app.run(debug=True, host='0.0.0.0', port=8888)
