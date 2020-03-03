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

if [ "${NGINX_METRICS_ENABLED}" = True ]; then
  sed -i "s/#stub_status/stub_status/g;" /etc/nginx/nginx.conf
  echo "Nginx metrics are enabled"
fi

if [ "${METRICS_HTTP_AUTH_PASSWORD}" != "" ]; then
  sed -i "s/#auth_basic/auth_basic/g;" /etc/nginx/nginx.conf
  rm -rf /etc/nginx/.htpasswd
  echo -n $METRICS_HTTP_AUTH_USER:$(openssl passwd -apr1 $METRICS_HTTP_AUTH_PASSWORD) >> /etc/nginx/.htpasswd
  echo "Basic auth is on for user ${HTTP_AUTH_LOGIN}..."
else
  echo "Basic auth is off (HTTP_AUTH_PASSWORD not provided)"
fi

echo "uwsgi_pass ${DD_UWSGI_PASS};" > /run/uwsgi_pass
echo "server ${DD_UWSGI_HOST}:${DD_UWSGI_PORT};" > /run/uwsgi_server
if [ "${USE_TLS}" == "True" ]
then
  exec nginx -c /etc/nginx/nginx_TLS.conf -g "daemon off;"
else
  exec nginx -g "daemon off;"
fi
