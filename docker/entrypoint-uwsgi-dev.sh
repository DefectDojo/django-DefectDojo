#!/bin/sh


# Copy settings.py (settings.py copied to allow for legacy installs and customizations)
cd /app
# TARGET_SETTINGS_FILE=dojo/settings/settings.py
# if [ ! -f ${TARGET_SETTINGS_FILE} ]; then
#   echo "Creating settings.py"
#   cp dojo/settings/settings.dist.py dojo/settings/settings.py
# fi

# Full list of uwsgi options: https://uwsgi-docs.readthedocs.io/en/latest/Options.html
# --lazy-apps required for debugging --> https://uwsgi-docs.readthedocs.io/en/latest/articles/TheArtOfGracefulReloading.html?highlight=lazy-apps#preforking-vs-lazy-apps-vs-lazy

exec uwsgi \
  "--${DD_UWSGI_MODE}" "${DD_UWSGI_ENDPOINT}" \
  --protocol uwsgi \
  --wsgi dojo.wsgi:application \
  --enable-threads \
  --processes 1 \
  --threads 1 \
  --reload-mercy 1 \
  --worker-reload-mercy 1 \
  --py-autoreload 1 \
  --buffer-size="${DD_UWSGI_BUFFER_SIZE:-8192}" \
  --lazy-apps

