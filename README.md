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
