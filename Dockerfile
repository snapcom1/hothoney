FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Expose ports
# 5060 - SIP (UDP)
# 8080 - HTTP Provisioning Honeypot
# 8081 - Web UI / API
EXPOSE 5060/udp
EXPOSE 8080
EXPOSE 8081

# Environment defaults
ENV DB_HOST=mariadb
ENV DB_PORT=3306
ENV DB_USER=honeypot
ENV DB_PASSWORD=honeypot
ENV DB_NAME=sip_honeypot
ENV SIP_PORT=5060
ENV HTTP_PORT=8080
ENV API_PORT=8081
ENV ADMIN_USER=admin
ENV ADMIN_PASS=changeme
ENV AUTO_BLOCK_THRESHOLD=3

# Run
CMD ["python", "main.py"]
