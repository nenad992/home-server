# 🖥️ Home Server Web – Lokalni razvoj i produkcija

---

## ⚙️ Potrebni alati (instaliraj jednom)

### 📌 Moraš imati sledeće instalirano:

- [Python 3.11+](https://www.python.org/downloads/)
- [Docker Desktop](https://www.docker.com/products/docker-desktop)
- [Tilt](https://docs.tilt.dev/install.html)
- [Git](https://git-scm.com/)

---

## 🧱 Prvi setup (samo jednom po novoj mašini)

```bash
git clone https://github.com/nenad992/home-server.git
cd home-server
pip install -r requirements.txt
```

---

## 🚀 Lokalni razvoj sa Tilt Up

Pokreni lokalnu aplikaciju unutar Docker-a:

```bash
tilt up
```

📍 Web aplikacija: [http://localhost:32777](http://localhost:32777)
📍 Tilt UI: [http://localhost:10350](http://localhost:10350)

> ⚠️ **Napomena:** Port 32777 je izabran da ne bi dolazilo do konflikta sa drugim projektima. Ova promena važi samo za lokalni razvoj preko Tilt-a i ne utiče na deployment/server.

### 🔧 Šta je poboljšano:

- **Bulletproof Tilt setup** - koristi `docker-compose.dev.yml` za stabilno pokretanje
- **Live reload** - automatski restart aplikacije kada promeniš kod
- **Conflict-free port** - port 32889 neće biti u konfliktu sa drugim projektima
- **Čisti logovi** - nema više 404 grešaka za favicon

---

## 🛑 Zaustavljanje

- U terminalu: `Ctrl + C`
- U Tilt UI: klikni `Down` pored `flask-app`

---

## 🔒 Šta se NE pokreće na serveru

- Tilt, Dockerfile i sve vezano za lokalni razvoj **nikada se ne koristi na Orange Pi**
- Server koristi samo `deploy.sh`, `app.py` i `templates/`
- Deploy se radi automatski iz `main` grane putem GitHub webhooka

---

# Home Server Dashboard

A comprehensive dashboard for monitoring and managing your home server infrastructure.

## Recent Improvements (v2.0)

### 🚀 Performance Optimizations

- **Intelligent Caching System**: Added background data fetching with smart caching to reduce load times
- **Tiered Update Intervals**:
  - Fast data (services, usage, docker): 30 seconds
  - Medium data (traffic, system info): 60 seconds
  - Slow data (network, bandwidth, security): 120 seconds
- **Reduced Dashboard Refresh**: From 10 minutes to 2 minutes with cached data
- **Background Data Updates**: Continuous background updates prevent stale data
- **Removed Heavy Components**: Eliminated filesystems section that was causing performance issues

### 🎨 Visual Enhancements

- **Improved Docker Containers**:
  - Progress bar visualization for running/stopped containers
  - Card-based layout with status indicators
  - Better container grouping and icons
- **Enhanced Network Section**:
  - Grouped active/inactive interfaces
  - Better visual hierarchy with colored cards
  - Status indicators with meaningful icons
- **Upgraded Bandwidth Monitoring**:
  - Card-based layout for total bandwidth overview
  - Individual interface performance metrics
  - Error detection with visual warnings
- **Loading Experience**:
  - Smooth loading overlay
  - Fade-in animations for better UX
  - Performance optimizations for mobile devices

### 🔧 Technical Improvements

- **Caching Architecture**: Thread-safe caching with configurable TTL
- **Background Worker**: Dedicated thread for data updates
- **Error Handling**: Graceful degradation when services are unavailable
- **Mobile Optimization**: Reduced animations and improved responsiveness

## Features

- **Server Monitoring**: Real-time status of TrueNAS server and Orange Pi
- **Service Management**: Start, stop, restart Docker services
- **Usage Statistics**: CPU, RAM, temperature monitoring
- **Network Overview**: Interface status and bandwidth monitoring
- **Docker Management**: Container status and quick actions
- **Security Monitoring**: Failed login attempts and SSH monitoring
- **System Alerts**: Real-time alerts and notifications
- **Login Activity**: Authentication tracking and reporting

## Quick Start

1. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

2. Configure environment:

   ```bash
   cp example.local.env .env
   # Edit .env with your settings
   ```

3. Run the dashboard:

   ```bash
   python app.py
   ```

4. Access the dashboard at `http://localhost:5000`

## Architecture

- **Flask Backend**: Python web framework
- **Real-time Updates**: AJAX polling with intelligent caching
- **Docker Integration**: Container monitoring and management
- **Telegram Notifications**: OTP authentication via Telegram
- **Responsive Design**: Bootstrap-based UI with custom animations

## Performance Notes

The dashboard now uses a smart caching system that dramatically improves load times:

- Initial page load: ~500ms (vs 3-5s previously)
- Data updates: ~200ms (vs 1-2s previously)
- Background updates prevent UI blocking
- Mobile performance optimized with reduced animations

## Contributing

Feel free to submit issues and enhancement requests!

---
