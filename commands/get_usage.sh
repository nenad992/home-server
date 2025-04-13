#!/bin/bash

# Lokalni (Orange Pi)
ORANGE_CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print 100 - $8}' | cut -d'.' -f1)
ORANGE_RAM_USED=$(free -m | awk '/Mem:/ {print $3}')
ORANGE_RAM_TOTAL=$(free -m | awk '/Mem:/ {print $2}')
ORANGE_TEMP=$(cat /sys/class/thermal/thermal_zone0/temp)
ORANGE_TEMP=$(echo "$ORANGE_TEMP / 1000" | bc)

# Izvrši get_usage_remote.sh direktno na glavnom serveru preko SSH
MAIN_OUTPUT=$(ssh root@192.168.0.50 'bash -s' < /mnt/Main_data/scripts/server_web_fallback/commands/get_usage_remote.sh)

echo '{
  "orange": {
    "cpu": '"$ORANGE_CPU"',
    "ram_used": '"$ORANGE_RAM_USED"',
    "ram_total": '"$ORANGE_RAM_TOTAL"',
    "temp": '"$ORANGE_TEMP"'
  },
  "main": '"$MAIN_OUTPUT"'
}'
