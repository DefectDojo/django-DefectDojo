#!/bin/sh


# Copy settings.py (settings.py copied to allow for legacy installs and customizations)
cd /app
TARGET_SETTINGS_FILE=dojo/settings/settings.py
if [ ! -f ${TARGET_SETTINGS_FILE} ]; then
  echo "Creating settings.py"
  cp dojo/settings/settings.dist.py dojo/settings/settings.py
fi

exec uwsgi \
  "--${DD_UWSGI_MODE}" "${DD_UWSGI_ENDPOINT}" \
  --protocol uwsgi \
  --wsgi dojo.wsgi:application \
  --enable-threads \
  --processes 2 \
  --threads 2 \
  --reload-mercy 1 \
  --worker-reload-mercy 1 \
  --py-autoreload 1 \
  --buffer-size="${DD_UWSGI_BUFFER_SIZE:-4096}"
