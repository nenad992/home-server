#!/bin/bash
cd /mnt/Main_data/scripts/server_web_fallback || exit 1
git pull origin main || exit 1
sleep 5
sudo systemctl restart server_web_fallback

# Loguj sve u telegram.log
echo ">>> Pokrećem Telegram notifikaciju..." >> telegram.log
/usr/bin/python3 /mnt/Main_data/scripts/server_web_fallback/telegram_notify.py >> telegram.log 2>&1
echo ">>> Gotovo ✅" >> telegram.log
