#!/bin/bash
#Script to manually create and push an image to docker 
set -ex

IMAGE_NAME="aweaver/defectdojo"
TAG="${1}"

docker build -t ${IMAGE_NAME}:${TAG} .
docker tag ${IMAGE_NAME}:${TAG} ${IMAGE_NAME}:latest
docker push ${IMAGE_NAME}
#docker tag ${REGISTRY}/${IMAGE_NAME}:latest ${REGISTRY}/${IMAGE_NAME}:${TAG}
#docker push ${REGISTRY}/${IMAGE_NAME}
