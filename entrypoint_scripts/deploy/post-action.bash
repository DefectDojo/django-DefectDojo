#!/bin/bash

if [ "$DOCKER_USER" != "" ] && [  "$DOCKER_PASS" != "" ] ; then
  if [ "$TRAVIS_BRANCH" == "master" ] ; then
    export REPO=appsecpipeline/django-defectdojo
  else
    BRANCH_TAG="devel-"
    export REPO=appsecpipeline/django-defectdojo-dev
  fi

  docker build -t $REPO "$REPO:$BRANCH_TAG$TRAVIS_TAG-mysql-self-contained" .

  if [ "$TRAVIS_BRANCH" == "master" ] ; then
    docker tag $REPO "$REPO:latest"
  fi
  docker login -u "$DOCKER_USER" -p "$DOCKER_PASS";
  docker push $REPO;

  docker build --target release -t $REPO:slim .
  docker tag $REPO "$REPO:$BRANCH_TAG$TRAVIS_TAG-slim"
  docker tag $REPO:slim slim
  docker login -u "$DOCKER_USER" -p "$DOCKER_PASS";
  docker push $REPO;
fi
