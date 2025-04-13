#!/bin/bash
SERVER_IP="192.168.0.50"

declare -A SERVICES=(
  ["Radarr"]=30025
  ["Bazarr"]=30046
  ["Overseerr"]=30002
  ["Photoprism"]=20800
  ["Prowlarr"]=30050
  ["qbittorent"]=30024
  ["Syncthing"]=20910
  ["Portainer"]=31015
  ["Sonarr"]=30113
  ["Pi-hole"]=20720
)


for name in "${!SERVICES[@]}"; do
  port=${SERVICES[$name]}
  nc -z -w2 $SERVER_IP $port && echo "$name: ✅" || echo "$name: ❌"
done
