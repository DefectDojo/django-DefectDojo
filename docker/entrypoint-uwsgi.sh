#!/bin/sh

# Allow for bind-mount setting.py overrides
FILE=/app/docker/extra_settings/settings.dist.py
if test -f "$FILE"; then
    echo "============================================================"
    echo "     Overriding DefectDojo's settings.dist.py with $FILE."
    echo "============================================================"
    cp "$FILE" /app/dojo/settings/settings.dist.py
fi

# Allow for bind-mount setting.py overrides
FILE=/app/docker/extra_settings/settings.py
if test -f "$FILE"; then
    echo "============================================================"
    echo "     Overriding DefectDojo's settings.py with $FILE."
    echo "============================================================"
    cp "$FILE" /app/dojo/settings/settings.py
fi

# Allow for bind-mount setting.py overrides
FILE=/app/docker/extra_settings/local_settings.py
if test -f "$FILE"; then
    echo "============================================================"
    echo "     Overriding DefectDojo's local_settings.py with $FILE."
    echo "============================================================"
    cp "$FILE" /app/dojo/settings/local_settings.py
fi

umask 0002

exec uwsgi \
  "--${DD_UWSGI_MODE}" "${DD_UWSGI_ENDPOINT}" \
  --protocol uwsgi \
  --enable-threads \
  --processes ${DD_UWSGI_NUM_OF_PROCESSES:-2} \
  --threads ${DD_UWSGI_NUM_OF_THREADS:-2} \
  --wsgi dojo.wsgi:application \
  --buffer-size="${DD_UWSGI_BUFFER_SIZE:-8192}" \
  --http 0.0.0.0:8081 --http-to ${DD_UWSGI_ENDPOINT}
  # HTTP endpoint is enabled for Kubernetes liveness checks. It should not be exposed as a serivce.

