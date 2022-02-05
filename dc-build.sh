#/bin/bash

if [ $# -eq 0 ]
then
    echo "Building docker compose"
else
    echo "Building docker compose with additional parameter $1 ..."
fi

# Building images for all configurations
# The docker build doesn't supply any environment variables to the Dockerfile, so we can use any profile.
docker-compose --profile mysql-rabbitmq --profile postgres-redis --env-file ./docker/environments/mysql-rabbitmq.env build $1
