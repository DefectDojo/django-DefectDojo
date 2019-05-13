#!/bin/bash

source ${BASH_SOURCE%/*}/../common-functions.bash
source ${BASH_SOURCE%/*}/../common-vars.bash


function target_k8s {
    echo $K8S_VERSION
    echo $MINIKUBE_VERSION
    echo $HELM_VERSION
    echo $CHANGE_MINIKUBE_NONE_USER
}


function target_docker {
    : # Do nothing
}


run_or_die target_"${TARGET}"
