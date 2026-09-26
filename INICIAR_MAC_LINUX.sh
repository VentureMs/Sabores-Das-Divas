#!/bin/sh
set -eu
cd "$(dirname "$0")"
printf '%s\n' 'SABORES DAS DIVAS — PRIMEIRO ACESSO / TESTE LOCAL'
python3 server.py seed-clients
python3 server.py bootstrap-admin
printf '%s\n' 'Abra http://127.0.0.1:8080 em seu navegador. Mantenha este terminal aberto.'
python3 server.py serve
