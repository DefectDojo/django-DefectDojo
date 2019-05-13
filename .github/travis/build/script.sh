#!/bin/bash

source ../common-functions.bash

# `set` flags:
# -e: exit as soon as one command returns a non-zero exit code
# -v: print all lines before executing them, to help identify which step failed
set -ev

function build_containers {
  # Build Docker images
  travis_fold start docker_image_build
  DOCKER_IMAGES=(django nginx)
  for docker_image in "${DOCKER_IMAGES[@]}"
  do
    docker build \
      --tag "defectdojo/defectdojo-${docker_image}:{TRAVIS_BUILD_NUMBER}" \
      --file "Dockerfile.${docker_image}" \
      .
    $? || error_and_exit "cannot build '${docker_image}' image"
  done
  travis_fold end docker_image_build
}


build_containers
