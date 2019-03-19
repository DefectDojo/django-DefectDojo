#!/bin/bash

ORG="defectdojo"

if { [ "${TRAVIS_TAG}" != "" ] || [ "${TRAVIS_EVENT_TYPE}" == "cron" ]; } && [ "${DOCKER_USER}" != "" ] && [  "${DOCKER_PASS}" != "" ]; then
  DOCKER_IMAGES=(django nginx)
  for docker_image in "${DOCKER_IMAGES[@]}"
  do
      # Cron pushed into branch-weekly-dev-image, triggered weekly
      if [ "${TRAVIS_EVENT_TYPE}" == "cron" ]; then
        TRAVIS_TAG=`date +%Y-%m-%d`
        REPO="${ORG}/weekly-${TRAVIS_BRANCH}-${ORG}-${docker_image}"
      elif [ ${TRAVIS_BRANCH} == "master" ]; then
        REPO="${ORG}/${ORG}-${docker_image}"
      else
        REPO="${ORG}/${TRAVIS_BRANCH}-${ORG}-${docker_image}"
      fi

      CONTAINER="${ORG}/${ORG}-${docker_image}"

      docker tag $CONTAINER $REPO:$TRAVIS_TAG
      docker login -u "$DOCKER_USER" -p "$DOCKER_PASS"
      docker push $REPO
  done
fi
