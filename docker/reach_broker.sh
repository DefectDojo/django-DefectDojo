#!/bin/bash

wait_for_broker_to_be_reachable() {
    echo -n "Waiting for broker to be reachable "
    failure_count=0
    DD_BROKER_READINESS_TIMEOUT=${DD_BROKER_READINESS_TIMEOUT:-10}
    while true;
    do 
        set +e
        celery --app=dojo status 2>/dev/null >/dev/null
        BROKER_TEST=$?
        set -e
        if [[ "$BROKER_TEST" == "0" ]]; then
            echo "Broker test was successful. Broker and at least one worker is connected."
            break
        fi
        if [[ "$BROKER_TEST" == "69" ]]; then
            echo "Broker test was successful. Broker is up. No worker is connected (but we are not testing that here)."
            break
        fi
        echo -n "."
        failure_count=$((failure_count + 1)) 
        if [ $DD_BROKER_READINESS_TIMEOUT = $failure_count ]; then
            echo "Broker test was failed:"
            # One more time with output
            celery --app=dojo status
            exit 1
        fi
    done
}
