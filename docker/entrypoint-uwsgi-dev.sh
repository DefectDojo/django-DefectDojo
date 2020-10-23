#!/bin/sh


# Copy settings.py (settings.py copied to allow for legacy installs and customizations)
cd /app
TARGET_SETTINGS_FILE=dojo/settings/settings.py
if [ ! -f ${TARGET_SETTINGS_FILE} ]; then
  echo "Creating settings.py"
  cp dojo/settings/settings.dist.py dojo/settings/settings.py
fi

UWSGI_INIFILE=dojo/uwsgi.ini
cat > $UWSGI_INIFILE<<EOF
[uwsgi]
$DD_UWSGI_MODE = $DD_UWSGI_ENDPOINT
protocol = uwsgi
module = dojo.wsgi:application
py-autoreload = 1
enable-threads
processes = ${DD_UWSGI_NUM_OF_PROCESSES:-2}
threads = ${DD_UWSGI_NUM_OF_THREADS:-2}
reload-mercy = 1
worker-reload-mercy = 1
threaded-logger
buffer-size = ${DD_UWSGI_BUFFER_SIZE:-4096}
EOF

if [ "${DD_LOGGING_FORMAT}" = "json_console" ]; then
    cat >> $UWSGI_INIFILE <<'EOF'
; logging as json does not offer full tokenization for requests, everything will be in message.
logger = stdio
log-encoder = json {"timestamp":${strftime:%%Y-%%m-%%d %%H:%%M:%%S%%z}, "source": "uwsgi", "message":"${msg}"}
log-encoder = nl
EOF
fi

exec uwsgi --ini $UWSGI_INIFILE
