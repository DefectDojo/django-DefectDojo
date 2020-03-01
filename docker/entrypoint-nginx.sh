#!/bin/bash

umask 0002
if [ "${GENERATE_TLS_CERTIFICATE}" == "True" ]
then
  openssl req  \
      -x509 \
      -nodes \
      -days 365 \
      -newkey rsa:4096 \
      -keyout /etc/nginx/ssl/nginx.key \
      -out /etc/nginx/ssl/nginx.crt \
      -subj "/C=DE/ST=City/L=City/O=Global Security/OU=IT Department/CN=nginx"

fi
echo "uwsgi_pass ${DD_UWSGI_PASS};" > /run/uwsgi_pass
echo "server ${DD_UWSGI_HOST}:${DD_UWSGI_PORT};" > /run/uwsgi_server
if [ "${USE_TLS}" == "True" ]
then
  exec nginx -c /etc/nginx/nginx_TLS.conf -g "daemon off;"
else
  exec nginx -g "daemon off;"
fi
