# DefectDojo on Kubernetes

## Issues in current image

* Self-contained all-in-one image is the opposite of how containerized apps
  should look like, which is that every container runs exactly one process.
* Gunicorn spawns additional worker processes. When using Gunicorn, worker
  processes should be set to 1 and scaling should be done via Kubernetes.
* Even when setting the Gunicorn workers to 1, that worker will still be forked.
  To prevent forking at all, uwsgi should be used instead of Gunicorn.
* Celery should be run in a separate container.
* Adding the whole repo directory to the image makes irrelevant changes cause
  a full rebuild and increases image size. Better explicitly name the files to
  be added instead of maintaining the .dockerignore.
* Celery uses SQLite that doesn't scale

## Build

```bash
docker build -t defectdojo-uwsgi -f Dockerfile.uwsgi .
docker build -t defectdojo-nginx -f Dockerfile.nginx .
docker build -t defectdojo-celery -f Dockerfile.celery .
docker build -t defectdojo-initializer -f Dockerfile.initializer .
```

## Run

The following describes how to run the docker images built above. This is not
intended for production use, but rather as a memo for creating a Helm chart.

```bash
# Network
docker network create defectdojo

#  PostgreSQL
docker run --rm -it --network=defectdojo \
  --name=defectdojo_postgresql \
  --network-alias postgresql \
  --env POSTGRES_DB=defectdojo \
  --env POSTGRES_USER=defectdojo \
  --env POSTGRES_PASSWORD=defectdojo \
  postgres

# Django application
docker run --rm -it --network=defectdojo \
  --name=defectdojo_uwsgi \
  --network-alias uwsgi \
  defectdojo-uwsgi

# RabbitMQ
docker run --rm -it --network=defectdojo \
  --name=defectdojo_rabbitmq \
  --network-alias rabbitmq \
  rabbitmq:3

# Create RabbitMQ user
docker exec -it defectdojo_rabbitmq \
  rabbitmqctl add_user defectdojo defectdojo

# Authorize RabbitMQ user
docker exec -it defectdojo_rabbitmq \
  rabbitmqctl set_permissions -p / defectdojo ".*" ".*" ".*"

# Celery
docker run --rm -it --network=defectdojo \
  --name=defectdojo_celery \
  --network-alias celery \
  --env CELERY_BROKER_URL='amqp://defectdojo:defectdojo@rabbitmq:5672//' \
  defectdojo-celery

# Nginx
docker run --rm -it --network=defectdojo \
  --name=defectdojo_nginx \
  --publish 8080:8080 \
  defectdojo-nginx

# Initializer
docker run --rm -it --network=defectdojo \
  --name defectdojo_initializer \
  defectdojo-initializer
```
