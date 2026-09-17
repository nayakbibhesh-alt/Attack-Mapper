FROM python:3.12-slim

# nmap isn't available on Render's native Python runtime, so this
# Docker build installs it explicitly.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Render sets $PORT at runtime; the shell form lets it expand.
CMD python3 -m attackmapper.webapp --host 0.0.0.0 --port $PORT --no-browser
