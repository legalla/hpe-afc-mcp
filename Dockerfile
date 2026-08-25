FROM python:3.12-slim

RUN useradd -m -u 1000 mcp
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY afc_client.py server.py ./

USER mcp

EXPOSE 8000

ENTRYPOINT ["python", "server.py"]
