#!/bin/bash

# Array of Docker images produced by this project,
# used to set '${image_name}' when looping over '${DOCKER_IMAGES[@]}',
# as in '${DOCKER_USER}/${IMAGE_PREFIX}-${image_name}:latest'
export DOCKER_IMAGES=(django nginx)

# Prefix for Docker images' names,
# as used in $'{DOCKER_USER}/${IMAGE_PREFIX}-${image_name}:latest'
export IMAGE_PREFIX='defectdojo'

# Remember to define 'DOCKER_USER', and 'DOCKER_PASS' - with "Display value in
# build log" disabled, in the 'Environment Variables' section of the Travis-CI
# 'Settings' for the repository. Otherwise, the 'Promote' stage won't be able
# to push images resulting from successful builds to the Docker Hub registry,
# and reuse them as a base to speed up subsequent build jobs.
export DOCKER_USER=${DOCKER_USER:-'local'}
