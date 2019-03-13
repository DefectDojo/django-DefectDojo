#!/bin/sh

C_FORCE_ROOT=true exec celery --app=dojo \
  worker \
  --pool=solo \
  --loglevel="${DD_CELERY_LOG_LEVEL}" \
  --concurrency=1
