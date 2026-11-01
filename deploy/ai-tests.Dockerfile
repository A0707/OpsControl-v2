# Image de tests uniquement ; construction explicite, jamais depuis le modèle ou le web.
FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends git openssh-client \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt requirements-dev.txt /tmp/
RUN python -m pip install --no-cache-dir -r /tmp/requirements.txt -r /tmp/requirements-dev.txt
ENV PYTHONDONTWRITEBYTECODE=1 INFRAOPS_AUTO_INTERVAL=0 INFRAOPS_INCIDENT_SYNC=0
USER 65534:65534
WORKDIR /src
ENTRYPOINT ["python"]
