FROM python:3.11-slim-bookworm AS build

WORKDIR /opt/securevault

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
        libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

COPY securevault/requirements.txt /opt/securevault/requirements.txt
RUN pip install --no-cache-dir -r /opt/securevault/requirements.txt


# -------- RELEASE --------

FROM python:3.11-slim-bookworm AS release

ENV FLASK_ENV=production
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /opt/securevault

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libffi8 \
        libssl3 \
        libpq5 \
        curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --chown=1001:1001 securevault/ /opt/securevault/
COPY --chown=1001:1001 docker-entrypoint.sh /opt/docker-entrypoint.sh

RUN useradd \
    --create-home \
    --home-dir /home/securevault \
    --shell /bin/bash \
    -u 1001 \
    securevault \
    && mkdir -p /home/securevault \
    && chown -R 1001:1001 /home/securevault \
    && chmod +x /opt/docker-entrypoint.sh

COPY --chown=1001:1001 --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /opt/securevault
ENV PYTHONPATH=/opt/securevault
ENV FLASK_APP=run.py

USER 1001

EXPOSE 8000

ENTRYPOINT ["/opt/docker-entrypoint.sh"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD curl -f http://localhost:8000 || exit 1
