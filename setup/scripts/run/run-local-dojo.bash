#!/bin/bash

function control_c()
# run if user hits control-c
{
  kill -15 $cpid $bpid $ppid
  exit $?
}

trap 'control_c' SIGINT

celery -A dojo worker -l info --concurrency 3 &
cpid=$!

celery beat -A dojo -l info &
bpid=$!

python manage.py runserver &
ppid=$!

tail -f /dev/null
