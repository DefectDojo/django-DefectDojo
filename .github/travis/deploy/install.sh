#!/bin/bash

source ${BASH_SOURCE%/*}/../common-functions.bash
source ${BASH_SOURCE%/*}/../common-vars.bash


function target_heroku {
    sudo curl https://cli-assets.heroku.com/install-ubuntu.sh | sh
}


run_or_die target_"${TARGET}"
