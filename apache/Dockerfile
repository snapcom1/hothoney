FROM httpd:2.4-alpine

# Install OpenSSL for certificate generation
RUN apk add --no-cache openssl

# Enable required modules
RUN sed -i \
    -e 's/^#\(LoadModule proxy_module\)/\1/' \
    -e 's/^#\(LoadModule proxy_http_module\)/\1/' \
    -e 's/^#\(LoadModule ssl_module\)/\1/' \
    -e 's/^#\(LoadModule rewrite_module\)/\1/' \
    -e 's/^#\(LoadModule headers_module\)/\1/' \
    -e 's/^#\(LoadModule socache_shmcb_module\)/\1/' \
    /usr/local/apache2/conf/httpd.conf

# Enable vhost include (SSL is configured in our vhost, not the default ssl.conf)
RUN echo "Include conf/extra/httpd-vhosts.conf" >> /usr/local/apache2/conf/httpd.conf

# Create SSL directory
RUN mkdir -p /usr/local/apache2/ssl

# Create log directory
RUN mkdir -p /var/log/apache2

# Copy custom vhost config
COPY httpd-vhost.conf /usr/local/apache2/conf/extra/httpd-vhosts.conf

# Generate self-signed certificate on first run if not provided
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 80 443

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["httpd-foreground"]
