# Runs the lab's own tools (test suite, attack scenarios, clinic map) so the
# only thing a laptop needs installed is Docker.
FROM python:3.13-slim
COPY --from=docker:29-cli /usr/local/bin/docker /usr/local/bin/docker
RUN pip install --no-cache-dir --root-user-action=ignore "PyYAML==6.0.3"
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
