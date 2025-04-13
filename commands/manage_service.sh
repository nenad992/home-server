#!/bin/bash

SERVICE_NAME=$1
ACTION=$2

if [ -z "$SERVICE_NAME" ] || [ -z "$ACTION" ]; then
  echo "Missing arguments"
  exit 1
fi

# lowercase action
ACTION=$(echo "$ACTION" | tr '[:upper:]' '[:lower:]')

# Mapa: Friendly name => Docker container name
declare -A CONTAINERS=(
  ["Radarr"]="ix-radarr-radarr-1"
  ["Bazarr"]="ix-bazarr-bazarr-1"
  ["Overseerr"]="ix-overseerr-overseerr-1"
  ["Photoprism"]="ix-photoprism-photoprism-1"
  ["Prowlarr"]="ix-prowlarr-prowlarr-1"
  ["qbittorent"]="ix-qbittorrent-qbittorrent-1"
  ["Syncthing"]="ix-syncthing-syncthing-1"
  ["Portainer"]="ix-portainer-portainer-1"
  ["Sonarr"]="ix-sonarr-sonarr-1"
  ["Pi-hole"]="ix-pihole-pihole-1"
)

CONTAINER=${CONTAINERS[$SERVICE_NAME]}

if [ -z "$CONTAINER" ]; then
  echo "Unknown service: $SERVICE_NAME"
  exit 1
fi

# Izvrši komandu na glavnom serveru
ssh root@192.168.0.50 "docker $ACTION $CONTAINER"

echo "$SERVICE_NAME $ACTION executed"
