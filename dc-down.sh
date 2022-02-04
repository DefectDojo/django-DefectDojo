#/bin/bash

if [ $# -eq 0 ]
  then
    echo "No profile supplied"
    exit 1
fi

if [ -z "$2" ]
then
    echo "Stopping docker compose with profile $1 ..."
    docker-compose --profile $1 --env-file ./docker/environments/$1.env down
else
    echo "Stopping docker compose with profiles $1 and $2 ..."
    docker-compose --profile $1 --env-file ./docker/environments/$1.env --profile $2 down
fi
