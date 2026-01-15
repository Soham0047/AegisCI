FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY . /app

RUN python -m pip install --upgrade pip \
    && pip install -e ".[dev]" \
    && python -m pip cache purge

ENV PORT=8080
EXPOSE 8080

CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
