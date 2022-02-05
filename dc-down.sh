#/bin/bash

echo "Stopping docker compose ..."

# Stopping containers for all configurations
# The environment must be provided but it doesn't make a difference which one
docker-compose --profile mysql-rabbitmq --profile postgres-redis --env-file ./docker/environments/mysql-rabbitmq.env down
