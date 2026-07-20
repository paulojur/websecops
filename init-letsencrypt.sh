#!/bin/bash

if ! docker compose version > /dev/null 2>&1; then
  echo 'Error: docker compose is not installed.' >&2
  exit 1
fi

domains="websecops.tech -d www.websecops.tech"
data_path="./certbot"

# 1. Parar o Nginx se estiver rodando
docker compose -f docker-compose.prod.yml stop nginx

# 2. Baixar os parametros SSL se não existirem
if [ ! -e "$data_path/conf/options-ssl-nginx.conf" ] || [ ! -e "$data_path/conf/ssl-dhparams.pem" ]; then
  echo "### Downloading recommended TLS parameters ..."
  mkdir -p "$data_path/conf"
  curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf > "$data_path/conf/options-ssl-nginx.conf"
  curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot/certbot/ssl-dhparams.pem > "$data_path/conf/ssl-dhparams.pem"
fi

# 3. Rodar Certbot no modo standalone (ele mesmo abre a porta 80 temporariamente)
echo "### Solicitando certificado oficial da Lets Encrypt..."
docker compose -f docker-compose.prod.yml run --rm -p 80:80 --entrypoint "certbot" certbot certonly --standalone \
    -d websecops.tech -d www.websecops.tech \
    --email admin@websecops.tech \
    --agree-tos \
    --force-renewal \
    --non-interactive

# 4. Iniciar Nginx agora que o certificado real existe
echo "### Subindo o Nginx com o certificado oficial..."
docker compose -f docker-compose.prod.yml up --force-recreate -d nginx
