#!/bin/bash

TAG=`if [ "$TRAVIS_BRANCH" == "master" ]; then echo "latest"; else echo $TRAVIS_BRANCH ; fi`
TRAVIS_TAG="1.5.4"

if { [ "${TRAVIS_TAG}" != "" ] || [ "${TRAVIS_EVENT_TYPE}" == "cron" ]; } && [ "${DOCKER_USER}" != "" ] && [  "${DOCKER_PASS}" != "" ]; then
  DOCKER_IMAGES=(django nginx)
  for docker_image in "${DOCKER_IMAGES[@]}"
  do
      if [ "${TRAVIS_EVENT_TYPE}" == "cron" ]; then
        TRAVIS_TAG=`date +%Y-%m-%d`
      fi
      REPO="defectdojo/defectdojo-${docker_image}"
      docker tag ${REPO} "defectdojo/${TRAVIS_BRANCH}-${docker_image}":$TRAVIS_TAG
      docker login -u "$DOCKER_USER" -p "$DOCKER_PASS"
      docker push ${REPO}
  done
fi
