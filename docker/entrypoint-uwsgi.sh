#!/bin/sh

umask 0002

exec uwsgi \
  "--${DD_UWSGI_MODE}" "${DD_UWSGI_ENDPOINT}" \
  --protocol uwsgi \
  --processes 4 \
  --wsgi dojo.wsgi:application
