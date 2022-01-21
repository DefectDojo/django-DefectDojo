#!/bin/sh

# Allow for bind-mount multiple settings.py overrides
FILES=$(ls -I README.md /app/docker/extra_settings)
NUM_FILES=$(echo "$FILES" | wc -l)
if [ "$NUM_FILES" -gt "1" ]; then
    COMMA_LIST=$(echo $FILES | tr -s '[:blank:]' ', ')
    echo "============================================================"
    echo "     Overriding DefectDojo's local_settings.py with multiple"
    echo "     Files: $COMMA_LIST"
    echo "============================================================"
    cp /app/docker/extra_settings/* /app/dojo/settings/
fi

umask 0002

# do the check with Django stack
python3 manage.py check

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

