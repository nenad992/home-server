from flask import Flask, render_template, request, redirect, url_for, session, abort, jsonify
import os, subprocess, time, socket
from threading import Thread
from wakeonlan import send_magic_packet
from datetime import timedelta, datetime
import hmac
import platform
import hashlib
import json
import re
import secrets
import requests
import threading
from collections import defaultdict

app = Flask(__name__)
# app.config['SESSION_COOKIE_DOMAIN'] = '.kucniserver.duckdns.org' 
app.secret_key = 'sda8@k!82nasd8r1sad129u1asdu1@##!' # kljuc sesije
app.permanent_session_lifetime = timedelta(days=30)  # sesija traje 30 dana

# Github
GITHUB_SECRET = b'a9S$8@x!kLm#2Z7rPq*3VgBz'  # ✅ bytes

# OTP Configuration (from telegram_notify.py)
TELEGRAM_BOT_TOKEN = "7854538488:AAE6zXA3LdjUrE8ZwC0ubAJ84PkOk_AERsY"
TELEGRAM_CHAT_ID = "-1002672470858"
OTP_VALIDITY_SECONDS = 120  # 2 minutes
OTP_LENGTH = 6

# In-memory storage for OTP data (in production, use Redis or database)
otp_storage = {}  # {session_id: {'otp': '123456', 'expires': timestamp, 'ip': 'x.x.x.x'}}
rate_limit_storage = defaultdict(list)  # {ip: [timestamp1, timestamp2, ...]}
otp_lock = threading.Lock()

# Rate limiting configuration
MAX_OTP_REQUESTS_PER_HOUR = 5  # Maximum OTP requests per IP per hour
MAX_OTP_REQUESTS_PER_MINUTE = 1  # Maximum OTP requests per IP per minute
MAX_LOGIN_ATTEMPTS = 3  # Maximum failed login attempts before temporary ban

# Glavni server
SERVER_IP = "192.168.0.50"
SERVER_MAC = "04:d4:c4:f2:a0:15"

# Dashboard caching system
dashboard_cache = {
    'data': {},
    'last_update': 0,
    'cache_duration': 60,  # Cache for 60 seconds
    'background_update_interval': 30,  # Update every 30 seconds in background
    'lock': threading.Lock()
}

# Cache keys for different update intervals
CACHE_KEYS = {
    'fast': ['services', 'usage', 'docker_stats'],  # Update every 30s
    'medium': ['traffic', 'system_info', 'alerts'],  # Update every 60s
    'slow': ['network', 'bandwidth', 'security', 'logins']  # Update every 120s
}

def get_cached_data(key, fetch_func, max_age=60):
    """Get data from cache or fetch if expired"""
    current_time = time.time()
    
    with dashboard_cache['lock']:
        if (key in dashboard_cache['data'] and 
            current_time - dashboard_cache['data'][key].get('timestamp', 0) < max_age):
            return dashboard_cache['data'][key]['data']
    
    # Fetch new data
    try:
        new_data = fetch_func()
        with dashboard_cache['lock']:
            dashboard_cache['data'][key] = {
                'data': new_data,
                'timestamp': current_time
            }
        return new_data
    except Exception as e:
        print(f"Error fetching {key}: {e}")
        # Return cached data if available, even if expired
        if key in dashboard_cache['data']:
            return dashboard_cache['data'][key]['data']
        return None

def background_data_updater():
    """Background thread to update dashboard data"""
    while True:
        try:
            if check_server_online():
                current_time = time.time()
                
                # Update fast data every 30s
                if current_time % 30 < 1:
                    for key in CACHE_KEYS['fast']:
                        if key == 'services':
                            get_cached_data('services', get_service_statuses, 30)
                        elif key == 'usage':
                            get_cached_data('usage', get_usage_data, 30)
                        elif key == 'docker_stats':
                            get_cached_data('docker_stats', get_detailed_docker_stats, 30)
                
                # Update medium data every 60s
                if current_time % 60 < 1:
                    for key in CACHE_KEYS['medium']:
                        if key == 'traffic':
                            get_cached_data('traffic', get_traffic_data, 60)
                        elif key == 'system_info':
                            get_cached_data('system_info', get_system_info, 60)
                        elif key == 'alerts':
                            get_cached_data('alerts', get_system_alerts, 60)
                
                # Update slow data every 120s
                if current_time % 120 < 1:
                    for key in CACHE_KEYS['slow']:
                        if key == 'network':
                            get_cached_data('network', get_network_interfaces, 120)
                        elif key == 'bandwidth':
                            get_cached_data('bandwidth', get_network_bandwidth, 120)
                        elif key == 'security':
                            get_cached_data('security', get_security_info, 120)
                        elif key == 'logins':
                            get_cached_data('logins', get_login_stats, 120)
            
        except Exception as e:
            print(f"Background updater error: {e}")
        
        time.sleep(5)  # Check every 5 seconds

def generate_otp():
    """Generate a secure random OTP"""
    return ''.join([str(secrets.randbelow(10)) for _ in range(OTP_LENGTH)])

def get_client_ip():
    """Get the real client IP address (handles proxies)"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr

def is_rate_limited(ip):
    """Check if IP is rate limited"""
    now = time.time()
    
    with otp_lock:
        # Clean old entries
        rate_limit_storage[ip] = [timestamp for timestamp in rate_limit_storage[ip] 
                                 if now - timestamp < 3600]  # Keep last hour
        
        # Check minute limit
        recent_minute = [timestamp for timestamp in rate_limit_storage[ip] 
                        if now - timestamp < 60]
        if len(recent_minute) >= MAX_OTP_REQUESTS_PER_MINUTE:
            return True, f"Too many requests. Wait {60 - int(now - min(recent_minute))} seconds."
        
        # Check hour limit
        if len(rate_limit_storage[ip]) >= MAX_OTP_REQUESTS_PER_HOUR:
            oldest = min(rate_limit_storage[ip])
            return True, f"Hourly limit exceeded. Try again in {int(3600 - (now - oldest))} seconds."
        
        return False, None

def add_rate_limit_entry(ip):
    """Add a rate limit entry for IP"""
    with otp_lock:
        rate_limit_storage[ip].append(time.time())

def send_otp_telegram(otp, ip):
    """Send OTP to Telegram group"""
    try:
        message = f"🔐 **Home Server Access Code**\n\n" \
                 f"**Code:** `{otp}`\n" \
                 f"**Valid for:** {OTP_VALIDITY_SECONDS} seconds\n" \
                 f"**From IP:** {ip}\n" \
                 f"**Time:** {datetime.now().strftime('%H:%M:%S')}\n\n" \
                 f"⚠️ If this wasn't you, someone is trying to access your server!"
        
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }
        
        response = requests.post(url, data=data, timeout=10)
        return response.status_code == 200
    except Exception as e:
        print(f"Telegram send error: {e}")
        return False

def create_otp_session(session_id, ip):
    """Create a new OTP session"""
    otp = generate_otp()
    expires = time.time() + OTP_VALIDITY_SECONDS
    
    with otp_lock:
        otp_storage[session_id] = {
            'otp': otp,
            'expires': expires,
            'ip': ip,
            'attempts': 0,
            'created_at': time.time()
        }
    
    return otp

def validate_otp(session_id, provided_otp, ip):
    """Validate provided OTP"""
    with otp_lock:
        if session_id not in otp_storage:
            return False, "No OTP session found"
        
        otp_data = otp_storage[session_id]
        
        # Check if expired
        if time.time() > otp_data['expires']:
            del otp_storage[session_id]
            return False, "OTP expired"
        
        # Check IP match for additional security
        if otp_data['ip'] != ip:
            return False, "Invalid session"
        
        # Check attempts
        if otp_data['attempts'] >= MAX_LOGIN_ATTEMPTS:
            del otp_storage[session_id]
            return False, "Too many failed attempts"
        
        # Validate OTP
        if otp_data['otp'] == provided_otp:
            del otp_storage[session_id]  # Clean up successful session
            return True, "Success"
        else:
            otp_storage[session_id]['attempts'] += 1
            remaining_attempts = MAX_LOGIN_ATTEMPTS - otp_data['attempts']
            return False, f"Invalid OTP. {remaining_attempts} attempts remaining"

def cleanup_expired_otps():
    """Clean up expired OTP sessions"""
    current_time = time.time()
    with otp_lock:
        expired_sessions = [session_id for session_id, data in otp_storage.items() 
                           if current_time > data['expires']]
        for session_id in expired_sessions:
            del otp_storage[session_id]

# Background cleanup task
def background_cleanup():
    """Background task to clean expired OTPs"""
    while True:
        time.sleep(60)  # Run every minute
        cleanup_expired_otps()

# Start background cleanup thread
cleanup_thread = threading.Thread(target=background_cleanup, daemon=True)
cleanup_thread.start()

def check_server_online():
    """Improved server status check using both ping and port check"""
    try:
        # First try ping
        if platform.system().lower() == "windows":
            ping_result = subprocess.call(['ping', '-n', '1', '-w', '2000', SERVER_IP], 
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
        else:
            ping_result = subprocess.call(['ping', '-c', '1', '-W', '2', SERVER_IP], 
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
        
        if not ping_result:
            return False
            
        # If ping works, also check if SSH port is accessible
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((SERVER_IP, 22))
        sock.close()
        return result == 0
        
    except Exception as e:
        print(f"Error checking server status: {e}")
        return False

def get_storage_data():
    """Get storage information from TrueNAS"""
    try:
        # Get disk usage information
        cmd = f'ssh -o ConnectTimeout=5 root@{SERVER_IP} "df -h | grep -E \'/mnt|/$\' && echo \'---\' && zpool list"'
        output = subprocess.check_output(cmd, shell=True, timeout=15).decode().strip()
        
        lines = output.split('\n')
        storage_data = {
            'filesystems': [],
            'zpools': [],
            'total_used': 0,
            'total_available': 0,
            'total_size': 0
        }
        
        zpool_section = False
        for line in lines:
            if '---' in line:
                zpool_section = True
                continue
                
            if not zpool_section and line.strip():
                # Parse filesystem data
                parts = line.split()
                if len(parts) >= 6 and parts[0] != 'Filesystem':
                    filesystem = {
                        'name': parts[0],
                        'size': parts[1],
                        'used': parts[2],
                        'available': parts[3],
                        'use_percent': parts[4],
                        'mountpoint': parts[5]
                    }
                    storage_data['filesystems'].append(filesystem)
            elif zpool_section and line.strip():
                # Parse zpool data
                parts = line.split()
                if len(parts) >= 3 and parts[0] != 'NAME':
                    zpool = {
                        'name': parts[0],
                        'size': parts[1],
                        'allocated': parts[2],
                        'free': parts[3] if len(parts) > 3 else 'N/A',
                        'health': parts[-1] if len(parts) > 4 else 'N/A'
                    }
                    storage_data['zpools'].append(zpool)
        
        return storage_data
    except Exception as e:
        print(f"Storage data error: {e}")
        return {'filesystems': [], 'zpools': [], 'total_used': 0, 'total_available': 0, 'total_size': 0}

def get_detailed_docker_stats():
    """Get detailed Docker container statistics from TrueNAS"""
    try:
        # Get container details with more information
        cmd = f'ssh -o ConnectTimeout=5 root@{SERVER_IP} "docker ps -a --format \'{{{{.Names}}}}|{{{{.Status}}}}|{{{{.Image}}}}|{{{{.Ports}}}}\' && echo \'---STATS---\' && docker stats --no-stream --format \'{{{{.Name}}}}|{{{{.CPUPerc}}}}|{{{{.MemUsage}}}}|{{{{.NetIO}}}}\'"'
        output = subprocess.check_output(cmd, shell=True, timeout=15).decode().strip()
        
        containers = []
        stats = {}
        total_containers = 0
        running_containers = 0
        cpu_total = 0.0
        memory_total = 0
        
        lines = output.split('\n')
        stats_section = False
        
        for line in lines:
            if '---STATS---' in line:
                stats_section = True
                continue
                
            if not stats_section and line.strip():
                # Parse container info
                parts = line.split('|')
                if len(parts) >= 2:
                    name = parts[0].strip()
                    status = parts[1].strip()
                    image = parts[2].strip() if len(parts) > 2 else 'N/A'
                    ports = parts[3].strip() if len(parts) > 3 else 'N/A'
                    
                    container = {
                        'name': name,
                        'status': status,
                        'image': image,
                        'ports': ports,
                        'running': 'Up' in status
                    }
                    containers.append(container)
                    total_containers += 1
                    if 'Up' in status:
                        running_containers += 1
            elif stats_section and line.strip():
                # Parse stats
                parts = line.split('|')
                if len(parts) >= 4:
                    name = parts[0].strip()
                    cpu = parts[1].strip().replace('%', '')
                    memory = parts[2].strip()
                    network = parts[3].strip()
                    
                    try:
                        cpu_val = float(cpu) if cpu != '--' else 0.0
                        cpu_total += cpu_val
                    except:
                        pass
                    
                    stats[name] = {
                        'cpu': cpu,
                        'memory': memory,
                        'network': network
                    }
        
        return {
            'containers': containers,
            'stats': stats,
            'total': total_containers,
            'running': running_containers,
            'stopped': total_containers - running_containers,
            'avg_cpu': round(cpu_total / max(running_containers, 1), 1) if running_containers > 0 else 0,
            'last_updated': datetime.now().strftime('%H:%M:%S')
        }
    except Exception as e:
        print(f"Detailed Docker stats error: {e}")
        return {'containers': [], 'stats': {}, 'total': 0, 'running': 0, 'stopped': 0, 'avg_cpu': 0, 'last_updated': 'Error'}

def get_network_interfaces():
    """Get detailed network interface information"""
    try:
        # Get network interface details
        cmd = f'ssh -o ConnectTimeout=5 root@{SERVER_IP} "ip addr show && echo \'---ROUTE---\' && ip route show default"'
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode().strip()
        
        interfaces = []
        default_gateway = "N/A"
        
        lines = output.split('\n')
        current_interface = None
        
        for line in lines:
            if '---ROUTE---' in line:
                continue
            if line.startswith('default'):
                parts = line.split()
                if len(parts) > 2:
                    default_gateway = parts[2]
                continue
                
            if re.match(r'^\d+:', line):
                # New interface
                parts = line.split()
                if len(parts) >= 2:
                    interface_name = parts[1].rstrip(':')
                    state = 'UP' if 'state UP' in line else 'DOWN'
                    current_interface = {
                        'name': interface_name,
                        'state': state,
                        'addresses': []
                    }
                    interfaces.append(current_interface)
            elif current_interface and 'inet ' in line:
                # IP address
                parts = line.strip().split()
                if len(parts) >= 2:
                    current_interface['addresses'].append(parts[1])
        
        return {
            'interfaces': interfaces,
            'default_gateway': default_gateway,
            'last_updated': datetime.now().strftime('%H:%M:%S')
        }
    except Exception as e:
        print(f"Network interfaces error: {e}")
        return {'interfaces': [], 'default_gateway': 'N/A', 'last_updated': 'Error'}

def get_system_info():
    """Get detailed system information"""
    try:
        # Get comprehensive system info
        cmd = f'ssh -o ConnectTimeout=5 root@{SERVER_IP} "uptime && echo \'---\' && free -h && echo \'---\' && lscpu | grep -E \'Model name|CPU\\(s\\)|Thread|Core\' && echo \'---\' && uname -a"'
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode().strip()
        
        sections = output.split('---')
        
        uptime_info = "N/A"
        memory_info = {}
        cpu_info = {}
        system_info = "N/A"
        
        if len(sections) >= 1:
            uptime_info = sections[0].strip()
        
        if len(sections) >= 2:
            # Parse memory info
            memory_lines = sections[1].strip().split('\n')
            for line in memory_lines:
                if 'Mem:' in line:
                    parts = line.split()
                    if len(parts) >= 7:
                        memory_info = {
                            'total': parts[1],
                            'used': parts[2],
                            'free': parts[3],
                            'shared': parts[4],
                            'cache': parts[5],
                            'available': parts[6]
                        }
        
        if len(sections) >= 3:
            # Parse CPU info
            cpu_lines = sections[2].strip().split('\n')
            for line in cpu_lines:
                if 'Model name:' in line:
                    cpu_info['model'] = line.split(':', 1)[1].strip()
                elif 'CPU(s):' in line:
                    cpu_info['count'] = line.split(':', 1)[1].strip()
                elif 'Core(s) per socket:' in line:
                    cpu_info['cores'] = line.split(':', 1)[1].strip()
                elif 'Thread(s) per core:' in line:
                    cpu_info['threads'] = line.split(':', 1)[1].strip()
        
        if len(sections) >= 4:
            system_info = sections[3].strip()
        
        return {
            'uptime': uptime_info,
            'memory': memory_info,
            'cpu': cpu_info,
            'system': system_info,
            'last_updated': datetime.now().strftime('%H:%M:%S')
        }
    except Exception as e:
        print(f"System info error: {e}")
        return {'uptime': 'N/A', 'memory': {}, 'cpu': {}, 'system': 'N/A', 'last_updated': 'Error'}

def get_usage_data():
    try:
        output = subprocess.check_output(
            ["/mnt/Main_data/scripts/server_web_fallback/commands/get_usage.sh"],
            timeout=10
        ).decode()
        return json.loads(output)
    except Exception as e:
        print(f"Usage error: {e}")
        return {}

def get_traffic_data():
    try:
        output = subprocess.check_output(
            ["/mnt/Main_data/scripts/server_web_fallback/commands/get_traffic.sh"],
            timeout=10
        ).decode()
        return json.loads(output)
    except Exception as e:
        print(f"Traffic error: {e}")
        return {}

def get_login_stats():
    try:
        output = subprocess.check_output(
            ["/mnt/Main_data/scripts/server_web_fallback/commands/get_login_stats.sh"],
            timeout=5
        ).decode()
        return json.loads(output)
    except Exception as e:
        print(f"Login stats error: {e}")
        return {}

def get_docker_stats():
    """Get Docker container statistics from TrueNAS"""
    try:
        # Get all containers
        cmd = f'ssh -o ConnectTimeout=5 root@{SERVER_IP} "docker ps -a --format \'{{{{.Names}}}}:{{{{.Status}}}}\'"'
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode().strip()
        
        containers = {}
        total_containers = 0
        running_containers = 0
        
        for line in output.splitlines():
            if ':' in line:
                name, status = line.split(':', 1)
                containers[name.strip()] = status.strip()
                total_containers += 1
                if 'Up' in status:
                    running_containers += 1
        
        return {
            'containers': containers,
            'total': total_containers,
            'running': running_containers,
            'stopped': total_containers - running_containers
        }
    except Exception as e:
        print(f"Docker stats error: {e}")
        return {'containers': {}, 'total': 0, 'running': 0, 'stopped': 0}

@app.route('/shutdown', methods=['POST'])
def shutdown():
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        subprocess.check_call(["/mnt/Main_data/scripts/server_web_fallback/commands/shutdown.sh"], timeout=10)
        return jsonify({'success': True, 'message': 'Shutdown command sent'}), 200
    except Exception as e:
        print(f"Shutdown error: {e}")
        return jsonify({'error': 'Failed to shutdown'}), 500

@app.route('/restart', methods=['POST'])
def restart():
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        subprocess.check_call(["/mnt/Main_data/scripts/server_web_fallback/commands/restart.sh"], timeout=10)
        return jsonify({'success': True, 'message': 'Restart command sent'}), 200
    except Exception as e:
        print(f"Restart error: {e}")
        return jsonify({'error': 'Failed to restart'}), 500

@app.route('/wakeup', methods=['POST'])
def wakeup():
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        send_magic_packet(SERVER_MAC)
        return jsonify({'success': True, 'message': 'Wake-on-LAN packet sent'}), 200
    except Exception as e:
        print(f"Wake-up error: {e}")
        return jsonify({'error': 'Failed to send wake-up packet'}), 500

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, redirect to dashboard
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    
    client_ip = get_client_ip()
    session_id = session.get('session_id', secrets.token_hex(16))
    session['session_id'] = session_id
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'request_otp':
            # Check rate limiting
            is_limited, limit_message = is_rate_limited(client_ip)
            if is_limited:
                return render_template('login.html', error=limit_message, 
                                     otp_requested=False, session_id=session_id)
            
            # Create OTP session
            otp = create_otp_session(session_id, client_ip)
            
            # Send OTP to Telegram
            if send_otp_telegram(otp, client_ip):
                add_rate_limit_entry(client_ip)
                
                # Log OTP request
                try:
                    log_path = "/mnt/Main_data/scripts/server_web_fallback/logs/login.log"
                    os.makedirs(os.path.dirname(log_path), exist_ok=True)
                    with open(log_path, 'a') as f:
                        f.write(f"otp_request|{int(time.time())}|{client_ip}\n")
                except:
                    pass
                
                return render_template('login.html', 
                                     otp_requested=True, 
                                     session_id=session_id,
                                     expires_at=time.time() + OTP_VALIDITY_SECONDS)
            else:
                return render_template('login.html', 
                                     error='Failed to send OTP. Please try again.',
                                     otp_requested=False, session_id=session_id)
        
        elif action == 'cancel_otp':
            # Cancel the current OTP session
            with otp_lock:
                if session_id in otp_storage:
                    del otp_storage[session_id]
            
            return render_template('login.html', 
                                 otp_requested=False,
                                 session_id=session_id)
        
        elif action == 'verify_otp':
            provided_otp = request.form.get('otp', '').strip()
            
            if not provided_otp:
                return render_template('login.html', 
                                     error='Please enter the OTP code',
                                     otp_requested=True, session_id=session_id)
            
            # Validate OTP
            is_valid, message = validate_otp(session_id, provided_otp, client_ip)
            
            if is_valid:
                session['logged_in'] = True
                session.permanent = True
                
                # Log successful login
                try:
                    log_path = "/mnt/Main_data/scripts/server_web_fallback/logs/login.log"
                    os.makedirs(os.path.dirname(log_path), exist_ok=True)
                    with open(log_path, 'a') as f:
                        f.write(f"success|{int(time.time())}|{client_ip}\n")
                except:
                    pass
                
                return redirect(url_for('dashboard'))
            else:
                # Log failed login
                try:
                    log_path = "/mnt/Main_data/scripts/server_web_fallback/logs/login.log"
                    os.makedirs(os.path.dirname(log_path), exist_ok=True)
                    with open(log_path, 'a') as f:
                        f.write(f"fail|{int(time.time())}|{client_ip}|{message}\n")
                except:
                    pass
                
                # Check if we still have an active OTP session
                with otp_lock:
                    has_active_session = (session_id in otp_storage and 
                                         time.time() <= otp_storage[session_id]['expires'])
                    expires_at = otp_storage[session_id]['expires'] if has_active_session else None
                
                return render_template('login.html', 
                                     error=message,
                                     otp_requested=has_active_session,
                                     session_id=session_id,
                                     expires_at=expires_at)
    
    # GET request - check if there's an active OTP session
    with otp_lock:
        has_active_session = (session_id in otp_storage and 
                             time.time() <= otp_storage[session_id]['expires'])
        expires_at = otp_storage[session_id]['expires'] if has_active_session else None
    
    return render_template('login.html', 
                         otp_requested=has_active_session,
                         session_id=session_id,
                         expires_at=expires_at)

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
    if not session.get('logged_in') and request.endpoint not in ['login', 'static', 'auth_check']:
        return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    online = check_server_online()
    
    # Use cached data for better performance
    if online:
        services = get_cached_data('services', get_service_statuses, 30) or {}
        usage = get_cached_data('usage', get_usage_data, 30) or {}
        traffic = get_cached_data('traffic', get_traffic_data, 60) or {}
        docker_stats = get_cached_data('docker_stats', get_detailed_docker_stats, 30) or {'containers': [], 'stats': {}, 'total': 0, 'running': 0, 'stopped': 0, 'avg_cpu': 0, 'last_updated': 'N/A'}
        # Remove storage data to improve performance - filesystems section removed
        network = get_cached_data('network', get_network_interfaces, 120) or {'interfaces': [], 'default_gateway': 'N/A', 'last_updated': 'N/A'}
        system_info = get_cached_data('system_info', get_system_info, 60) or {'uptime': 'N/A', 'memory': {}, 'cpu': {}, 'system': 'N/A', 'last_updated': 'N/A'}
        logins = get_cached_data('logins', get_login_stats, 120) or {}
        alerts = get_cached_data('alerts', get_system_alerts, 60) or {'alerts': [], 'count': 0, 'last_updated': 'N/A'}
        bandwidth = get_cached_data('bandwidth', get_network_bandwidth, 120) or {'interfaces': {}, 'total_rx': 0, 'total_tx': 0, 'last_updated': 'N/A'}
        security = get_cached_data('security', get_security_info, 120) or {'failed_logins': 0, 'active_connections': 0, 'firewall_status': 'N/A', 'last_login': 'N/A', 'ssh_attempts': [], 'last_updated': 'N/A'}
    else:
        # Offline fallback data
        services = {}
        usage = {}
        traffic = {}
        docker_stats = {'containers': [], 'stats': {}, 'total': 0, 'running': 0, 'stopped': 0, 'avg_cpu': 0, 'last_updated': 'N/A'}
        network = {'interfaces': [], 'default_gateway': 'N/A', 'last_updated': 'N/A'}
        system_info = {'uptime': 'N/A', 'memory': {}, 'cpu': {}, 'system': 'N/A', 'last_updated': 'N/A'}
        logins = {}
        alerts = {'alerts': [], 'count': 0, 'last_updated': 'N/A'}
        bandwidth = {'interfaces': {}, 'total_rx': 0, 'total_tx': 0, 'last_updated': 'N/A'}
        security = {'failed_logins': 0, 'active_connections': 0, 'firewall_status': 'N/A', 'last_login': 'N/A', 'ssh_attempts': [], 'last_updated': 'N/A'}

    return render_template(
        "dashboard.html",
        online=online,
        services=services,
        usage=usage,
        traffic=traffic,
        docker_stats=docker_stats,
        network=network,
        system_info=system_info,
        logins=logins,
        alerts=alerts,
        bandwidth=bandwidth,
        security=security
    )

@app.route('/api/dashboard-data')
def api_dashboard_data():
    """API endpoint for real-time dashboard data updates"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401

    online = check_server_online()
    
    if not online:
        return jsonify({
            'online': False,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'message': 'Server offline'
        })
    
    try:
        # Use cached data for better performance
        data = {
            'online': True,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'services': get_cached_data('services', get_service_statuses, 30) or {},
            'usage': get_cached_data('usage', get_usage_data, 30) or {},
            'traffic': get_cached_data('traffic', get_traffic_data, 60) or {},
            'docker_stats': get_cached_data('docker_stats', get_detailed_docker_stats, 30) or {'containers': [], 'stats': {}, 'total': 0, 'running': 0, 'stopped': 0, 'avg_cpu': 0, 'last_updated': 'N/A'},
            'network': get_cached_data('network', get_network_interfaces, 120) or {'interfaces': [], 'default_gateway': 'N/A', 'last_updated': 'N/A'},
            'system_info': get_cached_data('system_info', get_system_info, 60) or {'uptime': 'N/A', 'memory': {}, 'cpu': {}, 'system': 'N/A', 'last_updated': 'N/A'},
            'logins': get_cached_data('logins', get_login_stats, 120) or {},
            'alerts': get_cached_data('alerts', get_system_alerts, 60) or {'alerts': [], 'count': 0, 'last_updated': 'N/A'},
            'bandwidth': get_cached_data('bandwidth', get_network_bandwidth, 120) or {'interfaces': {}, 'total_rx': 0, 'total_tx': 0, 'last_updated': 'N/A'},
            'security': get_cached_data('security', get_security_info, 120) or {'failed_logins': 0, 'active_connections': 0, 'firewall_status': 'N/A', 'last_login': 'N/A', 'ssh_attempts': [], 'last_updated': 'N/A'}
        }
        return jsonify(data)
    except Exception as e:
        return jsonify({
            'error': f'Failed to fetch data: {str(e)}',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }), 500

@app.route('/api/container-logs/<container_name>')
def api_container_logs(container_name):
    """API endpoint for container logs"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    lines = request.args.get('lines', 50, type=int)
    logs = get_container_logs(container_name, lines)
    return jsonify(logs)

@app.route('/api/quick-action', methods=['POST'])
def api_quick_action():
    """API endpoint for quick actions"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    action = request.json.get('action') if request.is_json else request.form.get('action')
    if not action:
        return jsonify({'error': 'Action required'}), 400
    
    result = execute_quick_action(action)
    return jsonify(result)

@app.route('/api/alerts')
def api_alerts():
    """API endpoint for system alerts"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    alerts = get_system_alerts()
    return jsonify(alerts)

@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    return redirect(url_for('login'))

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/auth_check')
def auth_check():
    if not session.get('logged_in'):
        return "Unauthorized", 401
    return "OK", 200

@app.route('/apps')
def apps():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    server_online = check_server_online()

    # Lokalna mreža → koristi IP adresu
    if request.host.startswith("192.168.") or request.host.startswith("localhost") or request.host.startswith("127.0.0.1"):
        base = f"http://{SERVER_IP}"
    else:
        base = "https://"

    apps = {
        "Radarr": f"{base}radarr.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:30025",
        "Sonarr": f"{base}sonarr.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:30113",
        "Overseerr": f"{base}overseerr.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:30002",
        "Bazarr": f"{base}bazarr.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:30046",
        "Prowlarr": f"{base}prowlarr.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:30050",
        "qBittorrent": f"{base}torrent.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:30024",
        "Portainer": f"{base}portainer.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:31015",
        "Nextcloud": f"{base}nextcloud.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:30027",
        "OnlyOffice": f"{base}office.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:30134",
        "File Browser": f"{base}files.kucniserver.duckdns.org" if base.startswith("https") else f"{base}:30051",
        "SQLite Web": f"{base}:8099",
        "Spisak Bot": f"{base}:5000"
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
    """Updated service status check to match actual Docker containers"""
    try:
        # Updated service to container mapping based on your docker ps output
        services_map = {
            "Radarr": "ix-radarr-radarr-1",
            "Sonarr": "ix-sonarr-sonarr-1", 
            "Overseerr": "ix-overseerr-overseerr-1",
            "Bazarr": "ix-bazarr-bazarr-1",
            "Prowlarr": "ix-prowlarr-prowlarr-1",
            "qBittorrent": "ix-qbittorrent-qbittorrent-1",
            "Portainer": "ix-portainer-portainer-1",
            "Nextcloud": "ix-nextcloud-nextcloud-1",
            "OnlyOffice": "ix-onlyoffice-document-server-onlyoffice-1",
            "File Browser": "ix-filebrowser-filebrowser-1",
            "Flaresolverr": "ix-flaresolverr-flaresolverr-1",
            "Tailscale": "ix-tailscale-tailscale-1"
        }
        
        # Get container statuses via SSH
        containers_cmd = f'ssh -o ConnectTimeout=5 root@{SERVER_IP} "docker ps -a --format \'{{{{.Names}}}}:{{{{.Status}}}}\'"'
        output = subprocess.check_output(containers_cmd, shell=True, timeout=10).decode().strip()
        
        container_statuses = {}
        for line in output.splitlines():
            if ':' in line:
                name, status = line.split(':', 1)
                container_statuses[name.strip()] = status.strip()
        
        # Map service names to their statuses
        services = {}
        for service_name, container_name in services_map.items():
            if container_name in container_statuses:
                status = container_statuses[container_name]
                services[service_name] = "✅" if "Up" in status else "❌"
            else:
                services[service_name] = "❌"
        
        return services
    except Exception as e:
        print(f"Service status error: {e}")
        return {}

@app.route("/service/<name>/<action>", methods=["POST"])
def manage_service(name, action):
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
        
    allowed_actions = ["start", "stop", "restart"]
    if action not in allowed_actions:
        return jsonify({'error': 'Invalid action'}), 400

    try:
        subprocess.check_call([
            "/mnt/Main_data/scripts/server_web_fallback/commands/manage_service.sh",
            name,
            action
        ], timeout=30)
        return jsonify({'success': True, 'message': f'{action} executed for {name}'}), 200
    except subprocess.CalledProcessError as e:
        print(f"Service management error: {e}")
        return jsonify({'error': f'Failed to {action} {name}'}), 500
    except subprocess.TimeoutExpired:
        return jsonify({'error': f'Timeout executing {action} for {name}'}), 500

def get_system_alerts():
    """Get system alerts and warnings"""
    try:
        alerts = []
        
        # Temperature alerts
        cmd = f'ssh -o ConnectTimeout=5 root@{SERVER_IP} "sensors | grep -E \'Core|temp\'"'
        try:
            output = subprocess.check_output(cmd, shell=True, timeout=10).decode().strip()
            for line in output.split('\n'):
                if 'Core' in line or 'temp' in line:
                    # Parse temperature (simple extraction)
                    if '+' in line and '°C' in line:
                        temp_str = line.split('+')[1].split('°C')[0]
                        try:
                            temp = float(temp_str)
                            if temp > 80:
                                alerts.append({
                                    'type': 'danger',
                                    'message': f'High temperature detected: {temp}°C',
                                    'icon': 'thermometer-high'
                                })
                            elif temp > 70:
                                alerts.append({
                                    'type': 'warning',
                                    'message': f'Elevated temperature: {temp}°C',
                                    'icon': 'thermometer-half'
                                })
                        except:
                            pass
        except:
            pass
        
        # Disk space alerts
        try:
            storage = get_storage_data()
            for fs in storage.get('filesystems', []):
                if fs.get('use_percent'):
                    usage = int(fs['use_percent'].replace('%', ''))
                    if usage > 90:
                        alerts.append({
                            'type': 'danger',
                            'message': f'Critical disk space: {fs["mountpoint"]} ({usage}%)',
                            'icon': 'hdd-fill'
                        })
                    elif usage > 80:
                        alerts.append({
                            'type': 'warning',
                            'message': f'Low disk space: {fs["mountpoint"]} ({usage}%)',
                            'icon': 'hdd'
                        })
        except:
            pass
        
        # Container health alerts
        try:
            docker_stats = get_detailed_docker_stats()
            stopped_containers = [c for c in docker_stats.get('containers', []) if not c.get('running')]
            if stopped_containers:
                alerts.append({
                    'type': 'warning',
                    'message': f'{len(stopped_containers)} containers are stopped',
                    'icon': 'box-seam'
                })
        except:
            pass
        
        return {
            'alerts': alerts,
            'count': len(alerts),
            'last_updated': datetime.now().strftime('%H:%M:%S')
        }
    except Exception as e:
        print(f"Alerts error: {e}")
        return {'alerts': [], 'count': 0, 'last_updated': 'Error'}

def get_container_logs(container_name, lines=50):
    """Get recent logs for a specific container"""
    try:
        cmd = f'ssh -o ConnectTimeout=5 root@{SERVER_IP} "docker logs --tail {lines} {container_name} 2>&1"'
        output = subprocess.check_output(cmd, shell=True, timeout=15).decode().strip()
        
        logs = []
        for line in output.split('\n'):
            if line.strip():
                logs.append({
                    'line': line.strip(),
                    'timestamp': datetime.now().strftime('%H:%M:%S')
                })
        
        return {
            'container': container_name,
            'logs': logs[-lines:],  # Keep only the requested number of lines
            'count': len(logs),
            'last_updated': datetime.now().strftime('%H:%M:%S')
        }
    except Exception as e:
        print(f"Container logs error for {container_name}: {e}")
        return {'container': container_name, 'logs': [], 'count': 0, 'last_updated': 'Error'}

def get_network_bandwidth():
    """Get network bandwidth usage statistics"""
    try:
        # Get interface statistics with more detail
        cmd = f'ssh -o ConnectTimeout=5 root@{SERVER_IP} "cat /proc/net/dev"'
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode().strip()
        
        interfaces = {}
        for line in output.split('\n')[2:]:  # Skip header lines
            if ':' in line:
                parts = line.split(':')
                iface = parts[0].strip()
                stats = parts[1].split()
                
                if len(stats) >= 16 and iface != 'lo':  # Skip loopback
                    interfaces[iface] = {
                        'rx_bytes': int(stats[0]),
                        'rx_packets': int(stats[1]),
                        'rx_errors': int(stats[2]),
                        'tx_bytes': int(stats[8]),
                        'tx_packets': int(stats[9]),
                        'tx_errors': int(stats[10]),
                        'rx_mb': round(int(stats[0]) / 1048576, 2),
                        'tx_mb': round(int(stats[8]) / 1048576, 2)
                    }
        
        return {
            'interfaces': interfaces,
            'total_rx': sum(iface['rx_mb'] for iface in interfaces.values()),
            'total_tx': sum(iface['tx_mb'] for iface in interfaces.values()),
            'last_updated': datetime.now().strftime('%H:%M:%S')
        }
    except Exception as e:
        print(f"Network bandwidth error: {e}")
        return {'interfaces': {}, 'total_rx': 0, 'total_tx': 0, 'last_updated': 'Error'}

def get_security_info():
    """Get security-related information"""
    try:
        security_data = {
            'failed_logins': 0,
            'active_connections': 0,
            'firewall_status': 'Unknown',
            'last_login': 'Unknown',
            'ssh_attempts': []
        }
        
        # Check SSH login attempts
        try:
            cmd = f'ssh -o ConnectTimeout=5 root@{SERVER_IP} "journalctl -u ssh --since=\\"1 hour ago\\" | grep -E \\"Failed|Accepted\\" | tail -10"'
            output = subprocess.check_output(cmd, shell=True, timeout=10).decode().strip()
            
            failed_count = 0
            for line in output.split('\n'):
                if 'Failed' in line:
                    failed_count += 1
                    # Extract IP if possible
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'from' and i + 1 < len(parts):
                            ip = parts[i + 1]
                            security_data['ssh_attempts'].append({
                                'type': 'failed',
                                'ip': ip,
                                'time': datetime.now().strftime('%H:%M')
                            })
                            break
            
            security_data['failed_logins'] = failed_count
        except:
            pass
        
        # Check active SSH connections
        try:
            cmd = f'ssh -o ConnectTimeout=5 root@{SERVER_IP} "who | wc -l"'
            output = subprocess.check_output(cmd, shell=True, timeout=5).decode().strip()
            security_data['active_connections'] = int(output)
        except:
            pass
        
        return {
            **security_data,
            'last_updated': datetime.now().strftime('%H:%M:%S')
        }
    except Exception as e:
        print(f"Security info error: {e}")
        return {'failed_logins': 0, 'active_connections': 0, 'firewall_status': 'Error', 
                'last_login': 'Error', 'ssh_attempts': [], 'last_updated': 'Error'}

def execute_quick_action(action):
    """Execute quick maintenance actions"""
    try:
        actions = {
            'docker-prune': 'docker system prune -f',
            'update-packages': 'apt update && apt list --upgradable',
            'restart-networking': 'systemctl restart networking',
            'check-disk': 'df -h && du -sh /var/log/*',
            'container-health': 'docker ps --format "table {{.Names}}\t{{.Status}}\t{{.RunningFor}}"'
        }
        
        if action not in actions:
            return {'success': False, 'error': 'Unknown action'}
        
        cmd = f'ssh -o ConnectTimeout=10 root@{SERVER_IP} "{actions[action]}"'
        output = subprocess.check_output(cmd, shell=True, timeout=30).decode().strip()
        
        return {
            'success': True,
            'action': action,
            'output': output,
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }
    except Exception as e:
        return {
            'success': False,
            'action': action,
            'error': str(e),
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }

# Start background updater thread after all functions are defined
background_thread = threading.Thread(target=background_data_updater, daemon=True)
background_thread.start()

if __name__ == "__main__":
    print("🔗 Pristupi aplikaciji na:", os.getenv("LOCAL_URL", "http://localhost:8888"))
    app.run(debug=True, host='0.0.0.0', port=8888)
