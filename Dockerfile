FROM python:3.11-slim-bookworm AS build

WORKDIR /opt/

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
        git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

COPY . /opt/
WORKDIR /opt/

RUN pip install --no-cache-dir -r ./CTFd/requirements.txt \
    && for d in CTFd/plugins/*; do \
        if [ -f "$d/requirements.txt" ]; then \
            pip install --no-cache-dir -r "$d/requirements.txt";\
        fi; \
    done;


# -------- RELEASE --------

FROM python:3.11-slim-bookworm AS release

WORKDIR /opt/

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libffi8 \
        libssl3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --chown=1001:1001 . /opt/
RUN ln -s /opt/CTFd/migrations /opt/migrations


RUN useradd \
    --no-log-init \
    --shell /bin/bash \
    -u 1001 \
    ctfd \
    && mkdir -p /var/log/CTFd /var/uploads \
    && chown -R 1001:1001 /var/log/CTFd /var/uploads /opt /opt/CTFd \
    && chmod +x /opt/docker-entrypoint.sh

COPY --chown=1001:1001 --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

#  THIS IS KEY
WORKDIR /opt
ENV PYTHONPATH=/opt
ENV FLASK_APP=CTFd

USER 1001

EXPOSE 8000

ENTRYPOINT ["/opt/docker-entrypoint.sh"]
