#!/bin/bash
if [ "$DOCKER_USER" != "" ] && [  "$DOCKER_PASS" != "" ] ; then
  if [ "$TRAVIS_BRANCH" == "dev" ] ; then
    BRANCH_TAG="devel-"
    export HUB_REPO=appsecpipeline/django-defectdojo-dev
  elif [ "$TRAVIS_BRANCH" == "master" ] ; then
    export HUB_REPO=appsecpipeline/django-defectdojo
  fi

  docker tag $REPO "$REPO:$BRANCH_TAG$TRAVIS_TAG-mysql-self-contained"
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
