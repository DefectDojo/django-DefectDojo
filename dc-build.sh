#/bin/bash

main=`docker-compose  version  --short | cut -d '.' -f 1`
minor=`docker-compose  version  --short | cut -d '.' -f 2`
current=`docker-compose  version  --short`

echo 'Checking docker-compose version'
if [[ $main -lt 1 ]]; then
  echo "$current is not supported docker-compose version, please upgrade to minimal supported version:1.28"
  exit 1
elif [[ $main -eq 1 ]]; then
  if [[ $minor -lt 28 ]]; then
    echo "$current is not supported docker-compose version, please upgrade to minimal supported version:1.28"
    exit 1
  fi
fi

echo 'Supported docker-compose version'

if [ $# -eq 0 ]
then
    echo "Building docker compose"
else
    echo "Building docker compose with additional parameter $1 ..."
fi

# Building images for all configurations
# The docker build doesn't supply any environment variables to the Dockerfile, so we can use any profile.
docker-compose --profile mysql-rabbitmq --profile postgres-redis --env-file ./docker/environments/mysql-rabbitmq.env build $1
