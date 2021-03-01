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

UWSGI_INIFILE=dojo/uwsgi.ini
cat > $UWSGI_INIFILE<<EOF
[uwsgi]
$DD_UWSGI_MODE = $DD_UWSGI_ENDPOINT
protocol = uwsgi
module = dojo.wsgi:application
enable-threads
processes = ${DD_UWSGI_NUM_OF_PROCESSES:-2}
threads = ${DD_UWSGI_NUM_OF_THREADS:-2}
threaded-logger
buffer-size = ${DD_UWSGI_BUFFER_SIZE:-4096}
; HTTP endpoint is enabled for Kubernetes liveness checks. It should not be exposed as a serivce.
http = 0.0.0.0:8081
http-to = ${DD_UWSGI_ENDPOINT}
EOF

if [ "${DD_LOGGING_HANDLER}" = "json_console" ]; then
    cat >> $UWSGI_INIFILE <<'EOF'
; logging as json does not offer full tokenization for requests, everything will be in message.
logger = stdio
log-encoder = json {"timestamp":"${strftime:%%Y-%%m-%%d %%H:%%M:%%S%%z}", "source": "uwsgi", "message":"${msg}"}
log-encoder = nl
EOF
fi

exec uwsgi --ini $UWSGI_INIFILE
