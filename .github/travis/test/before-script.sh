#!/bin/bash

source ${BASH_SOURCE%/*}/../common-functions.bash
source ${BASH_SOURCE%/*}/../common-vars.bash
source ${BASH_SOURCE%/*}/stage-vars.bash


function target_k8s {
    # Update Helm dependencies for DefectDojo
    echo_info 'updating Helm dependencies for DefectDojo...'
    sudo helm dependency update ./helm/defectdojo
    echo_success 'updating Helm dependencies for DefectDojo done.'

    # Set Helm settings for the broker
    case "${BROKER}" in
        rabbitmq)
            HELM_BROKER_SETTINGS=" \
                --set redis.enabled=false \
                --set rabbitmq.enabled=true \
                --set celery.broker=rabbitmq \
            "
            ;;
        redis)
            HELM_BROKER_SETTINGS=" \
                --set redis.enabled=true \
                --set rabbitmq.enabled=false \
                --set celery.broker=redis \
            "
            ;;
        *)
            error_and_exit "'BROKER' must be 'redis' or 'rabbitmq'"
            ;;
    esac

    # Set Helm settings for the database
    case "${DATABASE}" in
        mysql)
            HELM_DATABASE_SETTINGS=" \
                --set database=mysql \
                --set postgresql.enabled=false \
                --set mysql.enabled=true \
            "
            ;;
        postgresql)
            HELM_DATABASE_SETTINGS=" \
                --set database=postgresql \
                --set postgresql.enabled=true \
                --set mysql.enabled=false \
            "
            ;;
        *)
            error_and_exit "'DATABASE' must be 'mysql' or 'postgresql'"
            ;;
    esac

    # Install DefectDojo into Kubernetes and wait for it
    echo_info 'installing DefectDojo into Kubernetes...'
    sudo helm install \
         ./helm/defectdojo \
         --name=defectdojo \
         --set django.ingress.enabled=false \
         --set imagePullPolicy=Never \
         ${HELM_BROKER_SETTINGS} \
         ${HELM_DATABASE_SETTINGS}

    [ ${?} -ne 0 ] &&
        error_and_exit 'installing DefectDojo into Kubernetes failed.'

    echo_success 'installing DefectDojo into Kubernetes done.'

    echo_info 'waiting for DefectDojo to become ready...'
    # Timeout value so that the wait doesn't timeout the travis build (faster fail)
    local REMAINING_TRIES=20
    local WAIT_BETWEEN_TRIES=6 # in seconds

    local status=''
    until [ "${status}" = 'True' ] || [ ${REMAINING_TRIES} -eq 0 ]
    do
        echo -n '.' && sleep ${WAIT_BETWEEN_TRIES}
        REMAINING_TRIES=$((REMAINING_TRIES - 1))

        status=$(sudo kubectl get pod \
                      --selector=defectdojo.org/component=django \
                      -o 'jsonpath={.items[*].status.conditions[?(@.type=="Ready")].status}')
    done
    echo # new line after progress dots

    [ ${REMAINING_TRIES} -eq 0 ] &&
        error_and_exit 'timeout, DefectDojo took too long to become ready.'

    echo_success 'waiting for DefectDojo to become ready done.'

    echo_info 'uWSGI log:'
    sudo kubectl logs --selector=defectdojo.org/component=django -c uwsgi

    echo_success 'DefectDojo is up and running.'
    sudo kubectl get pods
}


function target_docker {
    : # Do nothing
}


run_or_die target_"${TARGET}"
