FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y netcat-openbsd sqlite3 && \
    rm -rf /var/lib/apt/lists/*

COPY proxy.py .
RUN mkdir -p /app/data

ENV PYTHONUNBUFFERED=1
CMD ["python", "proxy.py"]