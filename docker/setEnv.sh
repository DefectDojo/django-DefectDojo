#!/bin/bash

# docker-compose.*.yml files names and their position compared to this script.
# Here: in parent directory.
target_dir="${0%/*}/.."
override_link='docker-compose.override.yml'
override_file_dev='docker-compose.override.dev.yml'
override_file_unit_tests='docker-compose.override.unit_tests.yml'
override_file_ptvsd='docker-compose.override.ptvsd.yml'


# Get the current environment and tells what are the options
function show_current {
    get_current
    say_switch
}


# Get the current environment
# Output variable: current_env
function get_current {
    if [ -L ${override_link} ]
    then
        current_env=$(expr $(basename $(readlink -f docker-compose.override.yml)) : "^docker-compose.override.\(.*\).yml$")
    else
        current_env=release
    fi
}

# Tell to which environments we can switch
function say_switch {
    echo "Using '${current_env}' configuration."
    for one_env in dev unit_tests ptvsd release
    do
        if [ "${current_env}" != ${one_env} ]; then
            echo "-> You can switch to '${one_env}' with '${0} ${one_env}'"
        fi
    done
}


function set_release {
    get_current
    if [ "${current_env}" != release ]
    then
        # In release configuration there is no override file
        rm ${override_link}
        docker-compose down
        echo "Now using 'release' configuration."
    else
        echo "Already using 'release' configuration."
    fi
}


function set_dev {
    get_current
    if [ "${current_env}" != dev ]
    then
        rm -f ${override_link}
        ln -s ${override_file_dev} ${override_link}
        docker-compose down
        echo "Now using 'dev' configuration."
    else
        echo "Already using 'dev' configuration."
    fi
}

function set_unit_tests {
    get_current
    if [ "${current_env}" != unit_tests ]
    then
        rm -f ${override_link}
        ln -s ${override_file_unit_tests} ${override_link}
        docker-compose down
        echo "Now using 'unit_tests' configuration."
    else
        echo "Already using 'unit_tests' configuration."
    fi
}

function set_ptvsd {
    get_current
    if [ "${current_env}" != ptvsd ]
    then
        rm -f ${override_link}
        ln -s ${override_file_ptvsd} ${override_link}
        docker-compose down
        echo "Now using 'ptvsd' configuration."
    else
        echo "Already using 'ptvsd' configuration."
    fi
}

# Change directory to allow working with relative paths.
cd ${target_dir}

if [ ${#} -eq 1 ] && [[ 'dev unit_tests release ptvsd' =~ "${1}" ]]
then
    set_"${1}"
else
    show_current
fi
