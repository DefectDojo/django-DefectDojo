#!/bin/bash

ORG="defectdojo"

deploy_demo() {
  if [ "$HEROKU_TOKEN" != "" ]; then
    echo "Deploying demo environment"
    git clone https://github.com/DefectDojo/heroku-DefectDojo.git
    cd heroku-DefectDojo 
    docker build -t deploy --build-arg DD_IMAGE=latest .
    docker tag deploy registry.heroku.com/defectdojo-dev/web

    # Deploy
    docker login -u -p "$HEROKU_TOKEN" registry.heroku.com
    docker push registry.heroku.com/docker-travis-heroku/web
    heroku container:release web -a defectdojo-dev
  fi
}

deploy_demo

if { [ "${TRAVIS_TAG}" != "" ] || [ "${TRAVIS_EVENT_TYPE}" == "cron" ]; } && [ "${DOCKER_USER}" != "" ] && [  "${DOCKER_PASS}" != "" ]; then
  DOCKER_IMAGES=(django nginx)
  echo "Pushing to Docker Hub"
  for docker_image in "${DOCKER_IMAGES[@]}"
  do
      REPO="${ORG}/${ORG}-${docker_image}"
      echo "Pushing to: ${REPO}"
      # Cron pushed into branch-weekly-dev-image, triggered weekly
      if [ "${TRAVIS_EVENT_TYPE}" == "cron" ]; then
        TRAVIS_TAG=`date +%Y-%m-%d`-${TRAVIS_BRANCH}
        REPO="${ORG}/weekly-${ORG}-${docker_image}"
      elif [ ${TRAVIS_BRANCH} == "master" ]; then
        docker tag $CONTAINER $REPO:latest
      else
        TRAVIS_TAG=${TRAVIS_BRANCH}-${TRAVIS_TAG}
      fi

      CONTAINER="${ORG}/${ORG}-${docker_image}"

      docker tag $CONTAINER $REPO:$TRAVIS_TAG
      docker tag $CONTAINER $REPO:$TRAVIS_BUILD_ID
      docker login -u "$DOCKER_USER" -p "$DOCKER_PASS"
      docker push $REPO
  done
fi
