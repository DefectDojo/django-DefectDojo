#!/bin/sh

# Convert all environment variables with names ending in _FILE into the content of
# the file that they point at and use the name without the trailing _FILE.
# This can be used to carry in Docker secrets.
# Inspired by https://github.com/grafana/grafana-docker/pull/166
# But rewrote for /bin/sh
for VAR_NAME in $(env | grep '^DD_[^=]\+_FILE=.\+' | sed -r "s/([^=]*)_FILE=.*/\1/g"); do
    VAR_NAME_FILE="$VAR_NAME"_FILE
    if [ -n "$(eval echo "\$$VAR_NAME")" ]; then
        echo >&2 "WARNING: Both $VAR_NAME and $VAR_NAME_FILE are set. Content of $VAR_NAME will be overridden."
    fi
    echo "Getting secret $VAR_NAME from $(eval echo "\$$VAR_NAME_FILE")"
    export "$VAR_NAME"="$(cat "$(eval echo "\$$VAR_NAME_FILE")")"
    unset "$VAR_NAME_FILE"
done