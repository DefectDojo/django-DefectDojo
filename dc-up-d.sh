#/bin/bash

unset PROFILE

bash ./docker/docker-compose-check.sh
if [[ $? -eq 1 ]]; then exit 1; fi

if [ $# -eq 0 ]
then
    if [ -z $DD_PROFILE ]
    then
        echo "No profile supplied, running default: mysql-rabbitmq"
        PROFILE="mysql-rabbitmq"
        echo "Other supported profiles:
          mysql-rabbitmq*
          mysql-redis
          postgres-rabbitmq
          postgres-redis

        Usage example: ./dc-up-d.sh mysql-redis
        "
    else
        PROFILE=$DD_PROFILE
    fi
else
    PROFILE=$1
fi

echo "Starting docker compose with profile $PROFILE in the background ..."
docker-compose --profile $PROFILE --env-file ./docker/environments/$PROFILE.env up --no-deps -d
