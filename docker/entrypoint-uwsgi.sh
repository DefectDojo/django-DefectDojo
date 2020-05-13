#!/bin/sh

umask 0002

exec uwsgi \
  "--${DD_UWSGI_MODE}" "${DD_UWSGI_ENDPOINT}" \
  --protocol uwsgi \
  --enable-threads \
  --processes 2 \
  --threads 2 \
  --reload-mercy 1 \
  --worker-reload-mercy 1 \
  --wsgi dojo.wsgi:application
