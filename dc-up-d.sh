#/bin/bash

unset PROFILE

if [ $# -eq 0 ]
then
    if [ -z $DD_PROFILE ]
    then
        echo "No profile supplied"
        exit 1
    else
        PROFILE=$DD_PROFILE
    fi
else
    PROFILE=$1
fi

echo "Starting docker compose with profile $PROFILE in the background ..."
docker-compose --profile $PROFILE --env-file ./docker/environments/$PROFILE.env up --no-deps -d
