#!/bin/bash

source ${BASH_SOURCE%/*}/../common-functions.bash
source ${BASH_SOURCE%/*}/../common-vars.bash


function check_pr_targets {
    : # Do nothing
}


function check_code_base_quality {
    : # Do nothing
}


function check_unwanted_changes {
    : # Do nothing
}


function check_sast {
    error_and_exit 'only to demo allowed job failure'
}


run_or_die check_"${CHECK}"
