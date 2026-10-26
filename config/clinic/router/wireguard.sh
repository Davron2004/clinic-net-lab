#!/bin/bash
# Remote access VPN (WireGuard) for doctors working from home.
#   wg0  10.10.60.1/24, listening on UDP 51820 on the WAN (198.51.100.2)
#
# One laptop is enrolled: home-doctor, tunnel address 10.10.60.2. Keys are
# made at boot inside each machine (see clinic-wg); only public keys are
# exchanged. Being in the tunnel proves who you are. What you may reach
# through it is the firewall's decision (nftables.nft, chain from_remote).
set -euo pipefail

clinic-wg init router 10.10.60.1/24 51820
# On the router, allowed-ips is the one address this laptop may use inside
# the tunnel. WireGuard drops anything else it sends, so a tunnel user cannot
# pretend to be another machine.
clinic-wg peer home-doctor 10.10.60.2/32
