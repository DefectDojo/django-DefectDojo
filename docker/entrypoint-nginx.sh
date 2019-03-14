#!/bin/sh

umask 0002

echo "uwsgi_pass ${DD_UWSGI_PASS};" > /run/uwsgi_pass
echo "server ${DD_UWSGI_HOST}:${DD_UWSGI_PORT};" > /run/uwsgi_server
exec nginx -g "daemon off;"
