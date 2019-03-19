#!/bin/bash

TAG=`if [ "$TRAVIS_BRANCH" == "master" ]; then echo "latest"; else echo $TRAVIS_BRANCH ; fi`
TRAVIS_TAG=1.5.4
DOCKER_IMAGES=(django nginx)
for docker_image in "${DOCKER_IMAGES[@]}"
do
  if [ "${TRAVIS_TAG}" != "" ] && [ "${DOCKER_USER}" != "" ] && [  "${DOCKER_PASS}" != "" ]; then
    if [ "${TRAVIS_EVENT_TYPE}" == "cron" ]; then
      TRAVIS_TAG=`date +%Y-%m-%d`
    fi
    REPO="defectdojo/defectdojo-${docker_image}"
    docker tag ${REPO} "defectdojo/${TRAVIS_BRANCH}-${docker_image}":${TRAVIS_TAG}
    docker login -u "${DOCKER_USER}" -p "{$DOCKER_PASS}";
    docker push {$REPO};
  fi
done
