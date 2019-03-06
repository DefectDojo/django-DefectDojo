#!/bin/sh

C_FORCE_ROOT=yes exec celery -A dojo worker -l info --concurrency 3
