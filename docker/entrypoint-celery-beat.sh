#!/bin/sh

umask 0002

C_FORCE_ROOT=true exec celery \
  --app=dojo \
  beat
