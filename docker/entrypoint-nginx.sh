#!/bin/sh

echo "uwsgi_pass ${UWSGI_PASS};" > /run/uwsgi_pass
echo "server ${UWSGI_HOST}:${UWSGI_PORT};" > /run/uwsgi_server
exec nginx -g "daemon off;"
