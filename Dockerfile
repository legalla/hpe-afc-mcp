FROM python:3.12-slim

RUN useradd -m -u 1000 mcp
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY afc_client.py afc_auth.py afc_token_manager.py server.py ./

# Secrets volume mount point, owned by the non-root container user.
RUN mkdir -p /app/secrets && chown -R mcp:mcp /app/secrets

USER mcp

EXPOSE 8000

ENTRYPOINT ["python", "server.py"]
