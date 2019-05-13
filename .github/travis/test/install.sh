#!/bin/bash

source ${BASH_SOURCE%/*}/../common-functions.bash
source ${BASH_SOURCE%/*}/../common-vars.bash


function target_k8s {
    export K8S_VERSION=v1.13.4
    export MINIKUBE_VERSION=v0.35.0
    export HELM_VERSION=v2.13.0
    export CHANGE_MINIKUBE_NONE_USER=true
}


function target_docker {
    : # Do nothing
}


run_or_die target_"${TARGET}"
