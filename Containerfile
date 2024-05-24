FROM python:3.12-alpine

COPY ["requirements.txt", "cli.py", "/srv/"]
COPY ["commands/", "/srv/commands/"]

RUN set -ex; \
    apk update; \
    apk add --no-cache git; \
    \
    python3 -m pip install -r /srv/requirements.txt; \
    adduser --home=/srv --shell=/bin/false \
        --disabled-password --no-create-home monitor; \
    chmod 640 -R /srv/**.py; \
    chown monitor:monitor -R /srv/commands /srv/cli.py; \
    \
    rm -rf /var/cache/apk/*;

USER monitor
WORKDIR /srv

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python3", "/srv/cli.py"]
CMD ["-o", "--loglevel=INFO", "--interval=60", "/etc/monitor.conf"]
