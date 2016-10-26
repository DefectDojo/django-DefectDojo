#!/bin/bash
#Script to to push an image to docker from travis
#Don't push images from pull requests

REPO='appsecpipeline/dojo-base'
TAG='latest'

if [ -z "$DOCKER_PASS" ]; then
  echo "Docker password not specified"
else
  echo "Building image"
  docker build -t $REPO --file dojo-base.docker .
  echo "Pushing to Docker Hub"
  docker login -u '$DOCKER_USER' -p '$DOCKER_PASS'
  docker tag $REPO $REPO:$TAG
  docker push $REPO
fi
