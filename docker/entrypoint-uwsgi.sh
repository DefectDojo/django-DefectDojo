#!/bin/sh

# Allow for bind-mount setting.py overrides
FILE=/settings/settings.py
if test -f "$FILE"; then
    echo "============================================================"
    echo "     Overriding DefectDojo's settings.py with $FILE."
    echo "============================================================"
    cp "$FILE" /app/dojo/settings/settings.py
fi

umask 0002

exec uwsgi \
  "--${DD_UWSGI_MODE}" "${DD_UWSGI_ENDPOINT}" \
  --protocol uwsgi \
  --enable-threads \
  --processes ${DD_UWSGI_NUM_OF_PROCESSES:-2} \
  --threads ${DD_UWSGI_NUM_OF_THREADS:-2} \
  --wsgi dojo.wsgi:application \
  --buffer-size="${DD_UWSGI_BUFFER_SIZE:-4096}"
