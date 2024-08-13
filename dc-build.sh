#!/bin/bash

bash ./docker/docker-compose-check.sh
if [[ $? -eq 1 ]]; then exit 1; fi

if [ $# -eq 0 ]
then
    echo "Building docker compose"
    # Compose V2 integrates compose functions into the Docker platform,
    # continuing to support most of the previous docker-compose features
    # and flags. You can run Compose V2 by replacing the hyphen (-) with
    # a space, using docker compose, instead of docker-compose.
    docker compose build
else
    echo "Building docker compose with additional parameter $1 ..."
    # Compose V2 integrates compose functions into the Docker platform,
    # continuing to support most of the previous docker-compose features
    # and flags. You can run Compose V2 by replacing the hyphen (-) with
    # a space, using docker compose, instead of docker-compose.
    docker compose build "$1"
fi
