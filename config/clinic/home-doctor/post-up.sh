#!/bin/bash
# The remote doctor's laptop: a WireGuard VPN client with a split tunnel.
# Runs once at boot, after the laptop has its home internet address.
set -euo pipefail

clinic-wg init home-doctor 10.10.60.2/24
# allowed-ips on the laptop is what the tunnel is able to carry; routing
# (below) decides what actually goes into it.
clinic-wg peer router 0.0.0.0/0 198.51.100.2:51820

# Split tunnel: only clinic addresses go through the VPN. Everything else
# (ordinary web browsing) leaves through the home internet as usual, so the
# clinic does not carry the doctor's personal traffic.
ip route add 10.10.0.0/16 dev wg0

# Ready means the tunnel is really up, so the first test does not race the
# VPN handshake.
clinic-wg wait-handshake 60
