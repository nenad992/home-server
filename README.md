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

## 🚀 Lokalni razvoj sa Tilt

Pokreni lokalnu aplikaciju unutar Docker-a:

```bash
tilt up
```

📍 Web aplikacija: [http://localhost:8889](http://localhost:8889)  
📍 Tilt UI: [http://localhost:10350](http://localhost:10350)

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

