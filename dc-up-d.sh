#/bin/bash

unset PROFILE

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
