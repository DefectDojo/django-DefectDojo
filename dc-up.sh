#/bin/bash

if [ $# -eq 0 ]
  then
    echo "No profile supplied"
    exit 1
fi

if [ -z "$2" ]
then
    echo "Starting docker compose with profile $1 in the foreground ..."
    docker compose --profile $1 --env-file ./docker/environments/$1.env up
else
    echo "Starting docker compose with profiles $1 and $2 in the foreground ..."
    docker compose --profile $1 --env-file ./docker/environments/$1.env --profile $2 up
fi
