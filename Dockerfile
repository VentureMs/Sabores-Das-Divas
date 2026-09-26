FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SDD_DATA_DIR=/data SDD_BACKUP_DIR=/backups
WORKDIR /srv
COPY server.py clientes_iniciais.json ./
COPY web ./web
RUN groupadd -g 10001 divas && useradd --uid 10001 --gid 10001 --create-home divas \
    && mkdir -p /data /backups && chown -R divas:divas /data /backups /srv
USER divas
EXPOSE 8080
CMD ["python", "-u", "server.py", "serve"]
