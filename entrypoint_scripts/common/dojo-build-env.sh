#!/usr/bin/env bash

# Set up output text styles
export NONE='\033[00m'
export RED='\033[01;31m'
export GREEN='\033[01;32m'
export YELLOW='\033[01;33m'
export PURPLE='\033[01;35m'
export CYAN='\033[01;36m'
export WHITE='\033[01;37m'
export BOLD='\033[1m'
export UNDERLINE='\033[4m'

# Supported databases
MYSQL=1
POSTGRES=2

# Name of the application directory
export DOJO_APP_DIR_NAME="django-DefectDojo"
# Main DefectDojo directory
export DOJO_ROOT_DIR="/opt/$DOJO_APP_DIR_NAME"
# Scripts location
export DOJO_SCRIPTS_DIR="$DOJO_ROOT_DIR/scripts"
# Docker path at django-DefectDojo/docker
export DOJO_DOCKER_DIR="$DOJO_ROOT_DIR/docker"

# Perform some consistency checks
ERROR_COUNT=0
if [ ! -e $DOJO_ROOT_DIR ]; then
    echo "Ensure the DOJO_ROOT_DIR env variable is set to the root directory of this app (i.e. /opt/django-DefectDojo)" >&2
    ERROR_COUNT=$((ERROR_COUNT+1))
fi
if [ ! -e $DOJO_DOCKER_DIR ]; then
    echo "Ensure the DOJO_DOCKER_DIR env variable is set to the docker-script directory of this app (i.e. /opt/django-DefectDojo/docker)" >&2
    ERROR_COUNT=$((ERROR_COUNT+1))
fi
if [ ! -e $DOJO_SCRIPTS_DIR ]; then
    echo "Ensure the DOCKER_SCRIPTS_DIR env variable is set to the script directory of this app (i.e. /opt/django-DefectDojo/script)" >&2
    ERROR_COUNT=$((ERROR_COUNT+1))
fi

if [ "$ERROR_COUNT" != "0" ]; then
    echo "One of the root paths was not correct. Terminating..." >&2
    exit 254
fi
