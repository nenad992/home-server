#!/bin/bash
echo ">>> Prelazak u direktorijum"
cd /mnt/Main_data/scripts/server_web_fallback || exit 1

echo ">>> Povlačim promene sa Gita"
git pull origin main || exit 1

echo ">>> Čekam 5 sekundi..."
sleep 5

echo ">>> Restartujem server_web_fallback.service"
sudo systemctl restart server_web_fallback

echo ">>> Pokrećem Telegram notifikaciju..."
/usr/bin/python3 /mnt/Main_data/scripts/server_web_fallback/telegram_notify.py >> /mnt/Main_data/scripts/server_web_fallback/telegram.log 2>&1
echo ">>> Gotovo ✅" >> /mnt/Main_data/scripts/server_web_fallback/telegram.log
