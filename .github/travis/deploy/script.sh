#!/bin/bash

source ../common-functions.bash

# `set` flags:
# -e: exit as soon as one command returns a non-zero exit code
# -v: print all lines before executing them, to help identify which step failed
set -ev

function target_heroku {
}


function target_dockerhub {
}


run_or_die target_"${TARGET}"
