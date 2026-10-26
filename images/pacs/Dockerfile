# The clinic's image archive (PACS): Orthanc, a real open-source DICOM server,
# wrapped so it boots like every other lab machine (waits for its network
# cable, takes its address from the topology, signals when it is ready).
#
#   DICOM  4242  AE title "PACS": modalities send images here (C-STORE)
#   HTTP   8042  web viewer and REST API (login required)
ARG TAG=dev

# The lab's boot script and probes come from the node image built just before.
FROM clinic-net-lab/node:${TAG} AS node

# Pinned, multi-arch (amd64 + arm64) official Orthanc image.
FROM orthancteam/orthanc:26.9.1

ENV DEBIAN_FRONTEND=noninteractive PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
# Network tools the lab expects on every machine (address setup, probes).
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iputils-ping netcat-openbsd curl dnsutils procps \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --break-system-packages "pynetdicom==2.1.1" "pydicom==2.4.4"

COPY --from=node /usr/local/bin/clinic-entrypoint /usr/local/bin/clinic-probe \
                 /usr/local/bin/clinic-probe-dicom /usr/local/bin/clinic-dicom \
                 /usr/local/bin/clinic-probe-pacs-web /usr/local/bin/
COPY --from=node /usr/local/share/clinic/ /usr/local/share/clinic/
COPY rootfs/ /
RUN chmod +x /usr/local/bin/*

ENTRYPOINT ["/usr/local/bin/clinic-entrypoint"]
CMD []
