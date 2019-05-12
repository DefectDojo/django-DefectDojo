#!/bin/bash

source ../common-functions.bash

# `set` flags:
# -e: exit as soon as one command returns a non-zero exit code
# -v: print all lines before executing them, to help identify which step failed
set -ev

function target_k8s {
    echo $K8S_VERSION
    echo $MINIKUBE_VERSION
    echo $HELM_VERSION
    echo $CHANGE_MINIKUBE_NONE_USER
}


function target_docker {
}


run_or_die target_"${TARGET}"
