FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    iproute2 iputils-ping dnsutils net-tools tcpdump traceroute \
    && pip install scapy \
    && apt-get clean

COPY . /app/dns
ENV PYTHONPATH=/app

WORKDIR /app

#CMD ["ls"]