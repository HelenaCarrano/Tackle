FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends libzbar0 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY scripts ./scripts
COPY allowlist.txt .env.example ./

ENV DB_PATH=/data/triage.db EML_STORE=/data/eml ALLOWLIST_FILE=/data/allowlist.txt HOST=0.0.0.0 PORT=8080
VOLUME ["/data"]
EXPOSE 8080
CMD ["sh", "-c", "[ -f /data/allowlist.txt ] || cp allowlist.txt /data/allowlist.txt; python -m app.cli serve"]
