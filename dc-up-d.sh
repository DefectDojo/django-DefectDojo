#/bin/bash

unset FIRST_PROFILE
unset SECOND_PROFILE

if [ $# -eq 0 ]
then
    if [ -z $DD_PROFILE ]
    then
        echo "No profile supplied"
        exit 1
    else
        FIRST_PROFILE=$DD_PROFILE
    fi
else
    if [ -z $DD_PROFILE ]
    then
        FIRST_PROFILE=$1
        SECOND_PROFILE=$2
    else
        FIRST_PROFILE=$DD_PROFILE
        SECOND_PROFILE=$1
    fi
fi

if [ -z $SECOND_PROFILE ]
then
    echo "Starting docker compose with profile $FIRST_PROFILE in the background ..."
    docker-compose --profile $FIRST_PROFILE --env-file ./docker/environments/$FIRST_PROFILE.env up --no-deps -d
else
    echo "Starting docker compose with profiles $FIRST_PROFILE and $SECOND_PROFILE in the background ..."
    docker-compose --profile $FIRST_PROFILE --env-file ./docker/environments/$FIRST_PROFILE.env --profile $SECOND_PROFILE up --no-deps -d
fi
