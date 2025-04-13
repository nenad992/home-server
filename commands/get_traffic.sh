##!/bin/bash

# INTERFACES
ORANGE_IFACE="eth0"       # ← Orange Pi koristi eth0
MAIN_IFACE="enp2s0"       # ← TrueNAS koristi enp2s0
MAIN_IP="192.168.0.50"

# Orange Pi promet
ORANGE_RX=$(cat /sys/class/net/$ORANGE_IFACE/statistics/rx_bytes)
ORANGE_TX=$(cat /sys/class/net/$ORANGE_IFACE/statistics/tx_bytes)

# Glavni server promet (preko SSH)
MAIN_OUTPUT=$(ssh root@$MAIN_IP "cat /sys/class/net/$MAIN_IFACE/statistics/rx_bytes; echo '|'; cat /sys/class/net/$MAIN_IFACE/statistics/tx_bytes")

MAIN_RX=$(echo "$MAIN_OUTPUT" | head -n1)
MAIN_TX=$(echo "$MAIN_OUTPUT" | tail -n1)

echo '{
  "orange": {
    "rx": '"$ORANGE_RX"',
    "tx": '"$ORANGE_TX"'
  },
  "main": {
    "rx": '"$MAIN_RX"',
    "tx": '"$MAIN_TX"'
  }
}'
