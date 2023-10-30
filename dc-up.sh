#!/bin/bash

unset PROFILE

bash ./docker/docker-compose-check.sh
if [[ $? -eq 1 ]]; then exit 1; fi

if [ $# -eq 0 ]; then
    if [ -z $DD_PROFILE ]
    then
        echo "No profile supplied, running default: postgres-redis"
        PROFILE="postgres-redis"
        echo "Other supported profiles:
          postgres-redis*
          postgres-rabbitmq
          mysql-redis
          mysql-rabbitmq

        Usage example: ./dc-up.sh mysql-rabbitmq
        "
    else
        PROFILE=$DD_PROFILE
    fi
else
    PROFILE=$1
fi

echo "Starting docker compose with profile $PROFILE in the foreground ..."
docker-compose --profile $PROFILE --env-file ./docker/environments/$PROFILE.env up --no-deps
