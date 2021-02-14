FROM ubuntu
ENV SQUID_CACHE_DIR=/var/spool/squid \
    SQUID_LOG_DIR=/var/log/squid \
    SQUID_USER=proxy

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y squid squidguard wget \
 && rm -rf /var/lib/apt/lists/*

RUN chown -R proxy:proxy /var/lib/squidguard/db 
COPY entrypoint.sh /sbin/entrypoint.sh
COPY squid.conf /etc/squid/squid.conf
COPY squidGuard.conf /etc/squidguard/squidGuard.conf
COPY deny_domains /etc/squidguard/deny_domains

RUN chmod 755 /sbin/entrypoint.sh

EXPOSE 3128/tcp
ENTRYPOINT ["/sbin/entrypoint.sh"]