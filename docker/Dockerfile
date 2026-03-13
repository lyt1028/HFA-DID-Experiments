FROM registry.cn-hangzhou.aliyuncs.com/library/python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iputils-ping curl && \
    rm -rf /var/lib/apt/lists/*

COPY requirements-docker.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /app
