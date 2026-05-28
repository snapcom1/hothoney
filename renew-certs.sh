#!/bin/bash
# Stop Apache to free port 80 for standalone authenticator
cd /root/sip-honeypot
docker compose stop apache

# Renew all certificates
certbot renew --non-interactive

# Copy renewed certs to Apache SSL directory
cp /etc/letsencrypt/live/hothoney.snapcom.com/fullchain.pem /root/sip-honeypot/apache/ssl/server.crt
cp /etc/letsencrypt/live/hothoney.snapcom.com/privkey.pem /root/sip-honeypot/apache/ssl/server.key
chmod 644 /root/sip-honeypot/apache/ssl/server.crt
chmod 600 /root/sip-honeypot/apache/ssl/server.key

# Restart Apache with new certs
docker compose up -d apache
