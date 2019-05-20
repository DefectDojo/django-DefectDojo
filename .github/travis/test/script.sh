#!/bin/bash

source ${BASH_SOURCE%/*}/../common-functions.bash
source ${BASH_SOURCE%/*}/../common-vars.bash
source ${BASH_SOURCE%/*}/stage-vars.bash


function target_k8s {
    # Run integration tests
    echo_info 'running tests...'
    sudo helm test defectdojo

    [ ${?} -ne 0 ] &&
        error_and_exit 'running tests failed.'

    echo_success 'running tests...'

    echo_info 'integration tests results:'
    sudo kubectl logs defectdojo-unit-tests

    echo_info 'Pods:'
    sudo kubectl get pods

    # Uninstall DefectDojo
    echo "Deleting DefectDojo from Kubernetes"
    echo_info 'deleting DefectDojo from Kubernetes...'
    sudo helm delete defectdojo --purge &&
        sudo kubectl get pods

    [ ${?} -ne 0 ] &&
        error_and_exit 'deleting DefectDojo from Kubernetes failed.'

    echo_success 'deleting DefectDojo from Kubernetes done.'
}


function target_docker {
    echo_info "validating docker compose..."
    docker-compose -f docker-compose_base.yml -f docker-compose_uwsgi-"${VERSION}".yml up -d

    [ ${?} -ne 0 ] &&
        error_and_exit 'validating docker compose failed.'

    echo_success 'validating docker compose done.'

    # Wait for services to become available
    echo_info 'waiting for services to start...'
    sleep 80
    echo_info 'testing DefectDojo service...'
    curl -s -o '/dev/null' http://localhost:8080 -m 120
    echo_info 'Docker compose container status:'
    docker-compose -f docker-compose_base.yml -f docker-compose_uwsgi-"${VERSION}".yml ps
}


run_or_die target_"${TARGET}"
