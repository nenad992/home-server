#!/bin/bash

LOG_FILE="/mnt/Main_data/scripts/server_web_fallback/logs/login.log"

if [ ! -f "$LOG_FILE" ]; then
  echo '{}'
  exit 0
fi

TODAY=$(date +%s -d "00:00")
YESTERDAY=$(date +%s -d "yesterday 00:00")
SEVEN_DAYS_AGO=$(date +%s -d "7 days ago")

today_success=0
today_fail=0
yesterday_success=0
yesterday_fail=0
week_success=0
week_fail=0

while IFS="|" read -r type timestamp; do
  if [ "$timestamp" -ge "$TODAY" ]; then
    [[ "$type" == "success" ]] && ((today_success++)) || ((today_fail++))
  fi
  if [ "$timestamp" -ge "$YESTERDAY" ] && [ "$timestamp" -lt "$TODAY" ]; then
    [[ "$type" == "success" ]] && ((yesterday_success++)) || ((yesterday_fail++))
  fi
  if [ "$timestamp" -ge "$SEVEN_DAYS_AGO" ]; then
    [[ "$type" == "success" ]] && ((week_success++)) || ((week_fail++))
  fi
done < "$LOG_FILE"

echo "{
  \"today\": {\"success\": $today_success, \"fail\": $today_fail},
  \"yesterday\": {\"success\": $yesterday_success, \"fail\": $yesterday_fail},
  \"week\": {\"success\": $week_success, \"fail\": $week_fail}
}"
