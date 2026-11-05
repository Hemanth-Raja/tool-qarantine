# The Tool Quarantine control plane (web UI + orchestrator). It talks to the host's
# Docker daemon to create/destroy sandboxes, so run it with the docker socket mounted:
#   docker run -p 8000:8000 -v /var/run/docker.sock:/var/run/docker.sock tq-app
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends docker.io ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY tq/ ./tq/
COPY samples/ ./samples/
COPY sandbox/ ./sandbox/
ENV TQ_DATA_DIR=/data
EXPOSE 8000
CMD ["uvicorn", "tq.server:app", "--host", "0.0.0.0", "--port", "8000"]
