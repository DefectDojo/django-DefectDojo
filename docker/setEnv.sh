#!/bin/bash

# docker-compose.*.yml files names and their position compared to this script.
# Here: in parent directory.
target_dir="${0%/*}/.."
override_link='docker-compose.override.yml'
override_file_dev='docker-compose.override.dev.yml'
override_file_debug='docker-compose.override.debug.yml'
override_file_unit_tests='docker-compose.override.unit_tests.yml'
override_file_unit_tests_cicd='docker-compose.override.unit_tests_cicd.yml'
override_file_integration_tests='docker-compose.override.integration_tests.yml'


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
        # Check for Mac OSX 
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # readlink is not native to mac, so this will work in it's place.
            symlink=$(python3 -c "import os; print(os.path.realpath('docker-compose.override.yml'))")
        else
            # Maintain the cleaner way
            symlink=$(readlink -f docker-compose.override.yml)
        fi
        current_env=$(expr $(basename symlink) : "^docker-compose.override.\(.*\).yml$")
    else
        current_env=release
    fi
}

# Tell to which environments we can switch
function say_switch {
    echo "Using '${current_env}' configuration."
    for one_env in dev debug unit_tests integration_tests release
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
        docker-compose --profile mysql-rabbitmq --profile postgres-redis --env-file ./docker/environments/mysql-rabbitmq.env down
        # In release configuration there is no override file
        rm ${override_link}
        echo "Now using 'release' configuration."
    else
        echo "Already using 'release' configuration."
    fi
}


function set_dev {
    get_current
    if [ "${current_env}" != dev ]
    then
        docker-compose --profile mysql-rabbitmq --profile postgres-redis --env-file ./docker/environments/mysql-rabbitmq.env down
        rm -f ${override_link}
        ln -s ${override_file_dev} ${override_link}
        echo "Now using 'dev' configuration."
    else
        echo "Already using 'dev' configuration."
    fi
}

function set_debug {
    get_current
    if [ "${current_env}" != debug ]
    then
        docker-compose --profile mysql-rabbitmq --profile postgres-redis --env-file ./docker/environments/mysql-rabbitmq.env down
        rm -f ${override_link}
        ln -s ${override_file_debug} ${override_link}
        echo "Now using 'debug' configuration."
    else
        echo "Already using 'debug' configuration."
    fi
}

function set_unit_tests {
    get_current
    if [ "${current_env}" != unit_tests ]
    then
        docker-compose --profile mysql-rabbitmq --profile postgres-redis --env-file ./docker/environments/mysql-rabbitmq.env down
        rm -f ${override_link}
        ln -s ${override_file_unit_tests} ${override_link}
        echo "Now using 'unit_tests' configuration."
    else
        echo "Already using 'unit_tests' configuration."
    fi
}

function set_unit_tests_cicd {
    get_current
    if [ "${current_env}" != unit_tests_cicd ]
    then
        docker-compose --profile mysql-rabbitmq --profile postgres-redis --env-file ./docker/environments/mysql-rabbitmq.env down
        rm -f ${override_link}
        ln -s ${override_file_unit_tests_cicd} ${override_link}
        echo "Now using 'unit_tests_cicd' configuration."
    else
        echo "Already using 'unit_tests_cicd' configuration."
    fi
}

function set_integration_tests {
    get_current
    if [ "${current_env}" != integration_tests ]
    then
        docker-compose --profile mysql-rabbitmq --profile postgres-redis --env-file ./docker/environments/mysql-rabbitmq.env down
        rm -f ${override_link}
        ln -s ${override_file_integration_tests} ${override_link}
        echo "Now using 'integration_tests' configuration."
    else
        echo "Already using 'integration_tests' configuration."
    fi
}

# Change directory to allow working with relative paths.
cd ${target_dir}

if [ ${#} -eq 1 ] && [[ 'dev debug unit_tests unit_tests_cicd integration_tests release' =~ "${1}" ]]
then
    set_"${1}"
else
    show_current
fi
