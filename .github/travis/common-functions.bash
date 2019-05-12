#!/bin/bash

function travis_fold {
  local action="${1}"
  local name="${2}"

  echo -en "travis_fold:${action}:${name}\r"
}


function error_and_exit {
    local message=$"{0}"

    (>&2 echo "ERROR: ${message}")
    exit 1
}


function run_or_die {
    local func_name="${1}"

    if [ -n "$(declare -F ${func_name})" ]; then
        ${func_name}
    else
        error_and_exist "function '${func_name}' does not exit"
    fi
}
