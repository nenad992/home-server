#!/bin/bash
cd /mnt/Main_data/scripts/server_web_fallback || exit 1
git pull origin main || exit 1
sleep 5
sudo systemctl restart server_web_fallback
/usr/bin/python3 /mnt/Main_data/scripts/server_web_fallback/telegram_notify.py