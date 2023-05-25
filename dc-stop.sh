#!/bin/bash

bash ./docker/docker-compose-check.sh
if [[ $? -eq 1 ]]; then exit 1; fi

if [ $# -eq 0 ]
then
    echo "Stopping docker compose"
else
    echo "Stopping docker compose with additional parameter $1 ..."
fi

# Stopping containers for all configurations
# The environment must be provided but it doesn't make a difference which one
docker-compose --profile mysql-rabbitmq --profile postgres-redis --env-file ./docker/environments/mysql-rabbitmq.env stop $1
