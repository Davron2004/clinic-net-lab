#!/bin/bash
# The "before" picture: one flat office network, like a consumer router.
#   eth1  WAN uplink
#   eth2  the whole clinic, one subnet, no VLANs
set -euo pipefail
ip link set eth1 up
ip addr add 198.51.100.2/24 dev eth1
ip route add default via 198.51.100.1
ip link set eth2 up
ip addr add 10.10.0.1/24 dev eth2
