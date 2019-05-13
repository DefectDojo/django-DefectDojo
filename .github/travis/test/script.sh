#!/bin/bash

source ${BASH_SOURCE%/*}/../common-functions.bash
source ${BASH_SOURCE%/*}/../common-vars.bash


function target_k8s {
    : # Do nothing
}


function target_docker {
    : # Do nothing
}


run_or_die target_"${TARGET}"
