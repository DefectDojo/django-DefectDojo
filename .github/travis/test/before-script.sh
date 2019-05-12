#!/bin/bash

source ../common-functions.bash

# `set` flags:
# -e: exit as soon as one command returns a non-zero exit code
# -v: print all lines before executing them, to help identify which step failed
set -ev

function target_k8s {
    export K8S_VERSION=v1.13.4
    export MINIKUBE_VERSION=v0.35.0
    export HELM_VERSION=v2.13.0
    export CHANGE_MINIKUBE_NONE_USER=true
}


function target_docker {
}


run_or_die target_"${TARGET}"
