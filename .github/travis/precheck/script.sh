#!/bin/bash

source ../common-functions.bash

# `set` flags:
# -e: exit as soon as one command returns a non-zero exit code
# -v: print all lines before executing them, to help identify which step failed
set -ev

function check_pr_targets {
}


function check_code_base_quality {
}


function check_unwanted_changes {
}


function check_sast {
    exit 1 #FIXME: remove; only to demo allowed job failure
}


run_or_die check_"${CHECK}"
