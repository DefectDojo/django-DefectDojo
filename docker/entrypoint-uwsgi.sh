#!/bin/sh

exec uwsgi \
  "--${UWSGI_MODE}" "${UWSGI_ENDPOINT}" \
  --protocol uwsgi \
  --wsgi dojo.wsgi:application
