# The SIEM (security monitor): a Wazuh manager, and nothing else.
# No indexer and no Wazuh dashboard: the clinic map is the dashboard, fed by
# run/alerts.jsonl (see wazuh/integrations/custom-clinic.py). That keeps it
# small enough for a laptop and for CI.
ARG TAG=dev
FROM clinic-net-lab/node:${TAG} AS node

FROM wazuh/wazuh-manager:4.14.9

# iproute: to plug the machine into the lab network like every other node.
# iputils: ping, which the test suite uses to check the machine is on the network.
RUN dnf install -y iproute iputils && dnf clean all && rm -rf /var/cache/dnf
# Filebeat ships alerts to the Wazuh indexer, which we do not run.
RUN rm -rf /etc/services.d/filebeat

# The lab's tools (probes included), so the isolation tests can run on this
# machine too. The whole set, so a new probe can never be missing here.
COPY --from=node /usr/local/bin/clinic-* /usr/local/bin/

COPY rootfs/ /
RUN chmod +x /usr/local/bin/clinic-* /etc/services.d/clinic-ready/run

# Our Wazuh configuration, owned the way Wazuh expects.
COPY --chown=root:wazuh --chmod=0640 wazuh/etc/ossec.conf /var/ossec/etc/ossec.conf
COPY --chown=wazuh:wazuh --chmod=0660 wazuh/etc/rules/clinic_rules.xml /var/ossec/etc/rules/clinic_rules.xml
COPY --chown=root:wazuh --chmod=0750 wazuh/integrations/ /var/ossec/integrations/
# Pick up newly enrolled agents' keys within 2 seconds instead of 10, so an
# agent can connect soon after it enrolls (see delay_after_enrollment).
RUN echo "remoted.keyupdate_interval=2" >> /var/ossec/etc/local_internal_options.conf

ENTRYPOINT ["/usr/local/bin/clinic-siem"]
