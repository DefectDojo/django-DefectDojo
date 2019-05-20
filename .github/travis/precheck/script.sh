#!/bin/bash

source ${BASH_SOURCE%/*}/../common-functions.bash
source ${BASH_SOURCE%/*}/../common-vars.bash


function check_pr_targets {
    : # Do nothing
}


function check_code_base_quality {
    if [ "${TRAVIS_PULL_REQUEST}" = 'false' ]
    then
    echo_info "new writes to ${TRAVIS_REPO_SLUG}, linting everything..."
    flake8
    else
    echo_info "linting changes coming from ${TRAVIS_PULL_REQUEST_SLUG}..."
    flake8-diff
    fi

    [ ${?} -ne 0 ] && error_and_exit 'linting failed.'
}


function check_unwanted_changes {
    : # Do nothing
}


function check_sast {
    error_and_exit 'only to demo allowed job failure'
}


run_or_die check_"${CHECK}"
