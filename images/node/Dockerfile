# One image for every simulated machine in the clinic: the router/firewall,
# the switch, staff PCs, the EMR server, medical devices, printers, guests.
# Each container picks its personality from the ROLE environment variable.
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iputils-ping nftables conntrack ulogd2 ulogd2-json \
        dnsmasq-base udhcpc wireguard-tools \
        samba smbclient \
        python3 python3-pip openssl ca-certificates \
        netcat-openbsd socat curl dnsutils tcpdump procps tini \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --break-system-packages "pynetdicom==2.1.1" "pydicom==2.4.4"

COPY rootfs/ /
RUN chmod +x /usr/local/bin/*

# tini runs as process 1: it reaps finished background processes (probes,
# services) that would otherwise pile up as zombies, and passes signals on.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/clinic-entrypoint"]
