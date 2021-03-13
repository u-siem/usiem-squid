FROM ubuntu
ENV SQUID_CACHE_DIR=/var/spool/squid \
    SQUID_LOG_DIR=/var/log/squid \
    SQUID_USER=proxy

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y squid squidguard wget lighttpd\
 && rm -rf /var/lib/apt/lists/*

RUN chown -R proxy:proxy /var/lib/squidguard/db
COPY entrypoint.sh /sbin/entrypoint.sh
COPY squid.conf /etc/squid/squid.conf
COPY squidGuard.conf /etc/squidguard/squidGuard.conf
COPY lighttpd.conf /etc/lighttpd/lighttpd.conf

COPY deny_hack /var/lib/squidguard/db/hack
COPY deny_porn /var/lib/squidguard/db/porn
COPY deny_anonvpn /var/lib/squidguard/db/anonvpn
COPY deny_lingerie /var/lib/squidguard/db/lingerie
COPY denied.html /var/log/squid/denied.html

RUN chmod 755 /sbin/entrypoint.sh

EXPOSE 3128/tcp
ENTRYPOINT ["/sbin/entrypoint.sh"]