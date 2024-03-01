#!/bin/sh

. /secret-file-loader.sh

# Allow for bind-mount multiple settings.py overrides
FILES=$(ls /app/docker/extra_settings/* 2>/dev/null)
NUM_FILES=$(echo "$FILES" | wc -w)
if [ "$NUM_FILES" -gt 0 ]; then
    COMMA_LIST=$(echo "$FILES" | tr -s '[:blank:]' ', ')
    echo "============================================================"
    echo "     Overriding DefectDojo's local_settings.py with multiple"
    echo "     Files: $COMMA_LIST"
    echo "============================================================"
    cp /app/docker/extra_settings/* /app/dojo/settings/
    rm -f /app/dojo/settings/README.md
fi

umask 0002

# do the check with Django stack
python3 manage.py check

DD_UWSGI_LOGFORMAT_DEFAULT='[pid: %(pid)|app: -|req: -/-] %(addr) (%(dd_user)) {%(vars) vars in %(pktsize) bytes} [%(ctime)] %(method) %(uri) => generated %(rsize) bytes in %(msecs) msecs (%(proto) %(status)) %(headers) headers in %(hsize) bytes (%(switches) switches on core %(core))'

args=()

args+=("--${DD_UWSGI_MODE}")
args+=("${DD_UWSGI_ENDPOINT}")
args+=("--protocol")
args+=("uwsgi")
args+=("--enable-threads")
args+=("--processes")
args+=("${DD_UWSGI_NUM_OF_PROCESSES:-2}")
args+=("--threads")
args+=("${DD_UWSGI_NUM_OF_THREADS:-2}")
args+=("--wsgi")
args+=("dojo.wsgi:application")
args+=("--buffer-size")
args+=("${DD_UWSGI_BUFFER_SIZE:-8192}")
args+=("--http")
args+=("0.0.0.0:8081")
args+=("--http-to")
args+=("${DD_UWSGI_ENDPOINT}")
args+=("--logformat")
args+=("${DD_UWSGI_LOGFORMAT:-$DD_UWSGI_LOGFORMAT_DEFAULT}")

if [ -n "${DD_UWSGI_MAX_FD}" ]; then
    args+=("--max-fd")
    args+=("${DD_UWSGI_MAX_FD}")
fi

exec uwsgi "${args[@]}"
