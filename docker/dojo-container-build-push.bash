#!/bin/bash
#Script to to push an image to docker from travis
#Don't push images from pull requests
if [ "$TRAVIS_PULL_REQUEST" = "false" ]; then
  if [ -z "$DOCKER_PASS" ]; then
    echo "Docker password not specified"
  else
    echo "Pushing to Docker Hub"
    docker login -u $DOCKER_USER -p $DOCKER_PASS
    docker tag $REPO:$COMMIT $REPO:$TAG
    docker tag $REPO:$COMMIT $REPO:travis-$TRAVIS_BUILD_NUMBER
    docker push $REPO
  fi
fi
