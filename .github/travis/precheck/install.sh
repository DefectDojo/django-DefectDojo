#!/bin/bash

source ${BASH_SOURCE%/*}/../common-functions.bash
source ${BASH_SOURCE%/*}/../common-vars.bash


function check_pr_targets {
    : # Do nothing
}


function check_code_base_quality {
    # flake8-diff
    sudo pip install pep8 flake8 flake8-diff
}


function check_unwanted_changes {
    : # Do nothing
}


function check_sast {
    # Snyk
    curl -sL "https://deb.nodesource.com/setup_10.x" | sudo -E bash -
    sudo apt-get install nodejs
    sudo npm install -g snyk
}


run_or_die check_"${CHECK}"
