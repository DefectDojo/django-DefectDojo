#!/bin/bash

wait_for_database_to_be_reachable() {
    echo -n "Waiting for database to be reachable "
    failure_count=0
    exit_on_count=30
    until echo "select 1;" | python3 manage.py dbshell > /dev/null
    do 
    echo -n "."
    failure_count=$((failure_count + 1)) 
    sleep 1
    if [ $exit_on_count = $failure_count ]; then
        exit 1
    fi
    done
}