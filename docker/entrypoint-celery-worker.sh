#!/bin/sh

umask 0002

C_FORCE_ROOT=true exec celery \
  --app=dojo \
  worker \
  --loglevel="${DD_CELERY_LOG_LEVEL}" \
  --pool=solo \
  --concurrency=1
