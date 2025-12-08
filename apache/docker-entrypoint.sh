#!/bin/sh
set -e

SSL_DIR="/usr/local/apache2/ssl"
CERT_FILE="$SSL_DIR/server.crt"
KEY_FILE="$SSL_DIR/server.key"

# Generate self-signed certificate if not present
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "Generating self-signed SSL certificate..."

    # Use SERVER_NAME or default
    CN="${SERVER_NAME:-localhost}"

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=IT/CN=$CN" \
        -addext "subjectAltName=DNS:$CN,DNS:localhost,IP:127.0.0.1"

    echo "SSL certificate generated for: $CN"
fi

# Set proper permissions
chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

exec "$@"
