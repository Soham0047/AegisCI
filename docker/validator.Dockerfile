FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    git \
    nodejs \
    npm \
    portaudio19-dev && \
    rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir ruff pytest mypy

WORKDIR /repo
