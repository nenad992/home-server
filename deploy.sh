#!/bin/bash
cd /mnt/Main_data/scripts/server_web_fallback || exit 1
git pull origin main || exit 1
sudo systemctl restart server_web_fallback
