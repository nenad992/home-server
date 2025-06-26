#!/bin/bash

SERVICE_NAME=$1
ACTION=$2

if [ -z "$SERVICE_NAME" ] || [ -z "$ACTION" ]; then
  echo "Missing arguments"
  exit 1
fi

# lowercase action
ACTION=$(echo "$ACTION" | tr '[:upper:]' '[:lower:]')

# Updated mapping based on actual Docker containers
declare -A CONTAINERS=(
  ["Radarr"]="ix-radarr-radarr-1"
  ["Sonarr"]="ix-sonarr-sonarr-1"
  ["Overseerr"]="ix-overseerr-overseerr-1"
  ["Bazarr"]="ix-bazarr-bazarr-1"
  ["Prowlarr"]="ix-prowlarr-prowlarr-1"
  ["qBittorrent"]="ix-qbittorrent-qbittorrent-1"
  ["Portainer"]="ix-portainer-portainer-1"
  ["Nextcloud"]="ix-nextcloud-nextcloud-1"
  ["OnlyOffice"]="ix-onlyoffice-document-server-onlyoffice-1"
  ["File Browser"]="ix-filebrowser-filebrowser-1"
  ["Flaresolverr"]="ix-flaresolverr-flaresolverr-1"
  ["Tailscale"]="ix-tailscale-tailscale-1"
)

CONTAINER=${CONTAINERS[$SERVICE_NAME]}

if [ -z "$CONTAINER" ]; then
  echo "Unknown service: $SERVICE_NAME"
  exit 1
fi

# Convert action to Docker command
case $ACTION in
  "start")
    DOCKER_ACTION="start"
    ;;
  "stop")
    DOCKER_ACTION="stop"
    ;;
  "restart")
    DOCKER_ACTION="restart"
    ;;
  *)
    echo "Invalid action: $ACTION"
    exit 1
    ;;
esac

# Execute command on the main server with timeout
ssh -o ConnectTimeout=10 root@192.168.0.50 "timeout 30 docker $DOCKER_ACTION $CONTAINER"

echo "$SERVICE_NAME $ACTION executed"