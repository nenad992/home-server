#!/bin/bash

CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print 100 - $8}' | cut -d'.' -f1)
RAM_USED=$(free -m | awk '/Mem:/ {print $3}')
RAM_TOTAL=$(free -m | awk '/Mem:/ {print $2}')
TEMP=$(cat /sys/class/thermal/thermal_zone0/temp)
TEMP=$(echo "$TEMP / 1000" | bc)

echo '{
  "cpu": '"$CPU"',
  "ram_used": '"$RAM_USED"',
  "ram_total": '"$RAM_TOTAL"',
  "temp": '"$TEMP"'
}'
