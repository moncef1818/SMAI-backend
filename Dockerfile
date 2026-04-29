# Dockerfile
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir \
    -i https://mirrors.aliyun.com/pypi/simple/ \
    -r requirements.txt
COPY . .

EXPOSE 8000