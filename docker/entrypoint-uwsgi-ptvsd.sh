#!/bin/sh

umask 0002



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
  --py-autoreload 1 \
  --enable-threads --lazy-apps --honour-stdin \
  --buffer-size="${DD_UWSGI_BUFFER_SIZE:-4096}"
