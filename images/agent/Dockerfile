# A clinic machine with a Wazuh security agent installed: the node image plus
# the agent, which watches files and ships logs to the SIEM (security monitor).
# Used by the EMR server (watches the patient records) and the router (ships
# the firewall log). Which job it does is picked by WAZUH_PROFILE at boot.
ARG TAG=dev
FROM clinic-net-lab/node:${TAG}

# The agent comes from Wazuh's official package, pinned to the same version as
# the manager (an agent must never be newer than its manager). The checksums
# are the ones published in Wazuh's signed apt index for this version.
ARG WAZUH_VERSION=4.14.9-1
ARG TARGETARCH
RUN set -eu; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
        arm64) sum=7a8c36c9b6d2c2c22ed27e9dd467a27cc3cb32660109f98c2db1a3c39c9f7278; arch=arm64 ;; \
        amd64) sum=20178fe13fa8fa4742dd3db3a19efaeed15faa79749fc47f606ca61a7ccad1f4; arch=amd64 ;; \
        *) echo "no Wazuh agent package for this CPU"; exit 1 ;; \
    esac; \
    deb="wazuh-agent_${WAZUH_VERSION}_${arch}.deb"; \
    curl -fsSL -o "/tmp/$deb" "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/$deb"; \
    echo "$sum  /tmp/$deb" | sha256sum -c -; \
    apt-get update; \
    apt-get install -y --no-install-recommends "/tmp/$deb"; \
    rm -rf "/tmp/$deb" /var/lib/apt/lists/*

COPY rootfs/ /
RUN chmod +x /usr/local/bin/*
