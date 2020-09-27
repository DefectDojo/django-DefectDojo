#!/bin/sh

umask 0002

cp dojo/settings/settings.dist.py dojo/settings/settings.py

exec uwsgi \
  "--${DD_UWSGI_MODE}" "${DD_UWSGI_ENDPOINT}" \
  --protocol uwsgi \
  --enable-threads \
  --processes ${DD_UWSGI_NUM_OF_PROCESSES:-2} \
  --threads ${DD_UWSGI_NUM_OF_THREADS:-2} \
  --reload-mercy 1 \
  --worker-reload-mercy 1 \
  --wsgi dojo.wsgi:application \
  --buffer-size="${DD_UWSGI_BUFFER_SIZE:-4096}"
