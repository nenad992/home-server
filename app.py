from flask import Flask, render_template, request, redirect, url_for, session, abort
import os, subprocess, time
from wakeonlan import send_magic_packet
from datetime import timedelta
import hmac
import hashlib
# testing v2.0.0
# ttttttttttttt
app = Flask(__name__)
# app.config['SESSION_COOKIE_DOMAIN'] = '.kucniserver.duckdns.org'
app.secret_key = 'sda8@k!82nasd8r1sad129u1asdu1@##!' # kljuc sesije
app.permanent_session_lifetime = timedelta(days=30)  # sesija traje 30 dana

# Github
GITHUB_SECRET = b'a9S$8@x!kLm#2Z7rPq*3VgBz'

# Login podaci
USERNAME = "KucniAdmin" # test again
PASSWORD = "sara-2021"

# Glavni server
SERVER_IP = "192.168.0.50"
SERVER_MAC = "04:d4:c4:f2:a0:15"

@app.route('/', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))  # <-- ako si već ulogovan

    if request.method == 'POST':
        if request.form['username'] == USERNAME and request.form['password'] == PASSWORD:
            session.permanent = True
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        return render_template('login.html', error="Pogrešan login.")
    return render_template('login.html')

@app.before_request
def set_cookie_domain():
    if request.host.startswith("192.168."):
        app.config['SESSION_COOKIE_DOMAIN'] = None  # lokalni pristup (IP)
    else:
        app.config['SESSION_COOKIE_DOMAIN'] = ".kucniserver.duckdns.org"  # javni domen

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    online = subprocess.call(['ping', '-c', '1', '-W', '1', SERVER_IP], stdout=subprocess.DEVNULL) == 0
    return render_template('dashboard.html', online=online)

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

    payload = request.get_data()
    mac = hmac.new(GITHUB_SECRET, msg=payload, digestmod=hashlib.sha256)

    if not hmac.compare_digest(mac.hexdigest(), signature):
        abort(403, "Invalid signature")

    # Pokreni deploy skriptu
    subprocess.call(["/mnt/Main_data/scripts/server_web_fallback/deploy.sh"])
    return "OK", 200
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8888)
