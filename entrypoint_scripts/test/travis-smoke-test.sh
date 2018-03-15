#!/usr/bin/env bash
###
# This test script verifies entrypoint processes are startable and don't
# crash due to some misconfiguration
###

set -x

# Variable to hold the exit status
EXIT_STATUS=0

# Build the actual container
export DOJO_ADMIN_USER='admin'
export DOJO_ADMIN_PASSWORD='admin'
export CONTAINER_NAME=dojo
docker build -t $REPO .

# Launch one container per service
container_id_worker=$(docker run -d --entrypoint=celery $REPO worker -A dojo -l info -c 1 -P solo)
container_id_beat=$(docker run -d --entrypoint=celery $REPO beat -A dojo -l info)
container_id_server=$(docker run -d --entrypoint=python $REPO manage.py runserver 0.0.0.0:8000)

# Wait for the container to spin up and gie it some time to fail
sleep 10

# See whether containers came up or failed
for container_id in $container_id_worker $container_id_beat $container_id_server; do
    container_status=$(docker ps --filter "id=$container_id" --format "{{.Status}}")
    if [[ "$container_status" =~ ^"Up "[0-9]+\ .*$ ]]; then
        # Container is up, all good
        echo "Container came up; cleaning up..."
        docker exec $container_id ps aux
    else
        # Container did not come up, there must be a problem somewhere
        echo "Container did not come up; Trying to fetch the logs and cat them out"
        docker logs $container_id
        ((EXIT_STATUS+=1))
    fi
    
    # Clean up, once we're done with the container
    docker rm -f $container_id
done

exit $EXIT_STATUS
