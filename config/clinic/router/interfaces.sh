#!/bin/bash
# Router interfaces for the segmented clinic.
#   eth1  WAN, the clinic's internet uplink
#   eth2  trunk to the core switch; one 802.1Q sub-interface per VLAN
#         ("router on a stick": one cable, many networks)
set -euo pipefail

ip link set eth1 up
ip addr add 198.51.100.2/24 dev eth1
ip route add default via 198.51.100.1

ip link set eth2 up
vlan() {  # vlan <id> <gateway-address/prefix>
    ip link add link eth2 name "eth2.$1" type vlan id "$1"
    ip addr add "$2" dev "eth2.$1"
    ip link set "eth2.$1" up
}
vlan 10 10.10.10.1/24   # staff PCs (reception, doctors)
vlan 20 10.10.20.1/24   # servers (EMR, PACS)
vlan 30 10.10.30.1/24   # medical devices
vlan 40 10.10.40.1/24   # printers and fax
vlan 50 10.10.50.1/24   # guest Wi-Fi
vlan 90 10.10.90.1/24   # security monitoring (SIEM)
