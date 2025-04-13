#!/bin/bash
GIT_WORK_TREE=/mnt/Main_data/scripts/server_web_fallback
GIT_DIR=/mnt/Main_data/scripts/server_web_fallback/.git
echo ">>> Pulling latest code..."
git --work-tree=$GIT_WORK_TREE --git-dir=$GIT_DIR pull origin main
echo ">>> Restarting service..."
systemctl restart server_web_fallback
