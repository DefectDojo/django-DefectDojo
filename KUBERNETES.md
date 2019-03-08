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

## Build images

```zsh
docker build -t defectdojo/defectdojo-uwsgi -f Dockerfile.uwsgi .
docker build -t defectdojo/defectdojo-nginx -f Dockerfile.nginx .
docker build -t defectdojo/defectdojo-celery -f Dockerfile.celery .
docker build -t defectdojo/defectdojo-initializer -f Dockerfile.initializer .
docker push defectdojo/defectdojo-uwsgi
docker push defectdojo/defectdojo-nginx
docker push defectdojo/defectdojo-celery
docker push defectdojo/defectdojo-initializer
```

## Run with Kubernetes

```zsh
minikube start
minikube addons enable ingress
helm init
helm repo update
helm dependency update ./helm/defectdojo

# Create a TLS secret called defectdojo-tls according to
# <https://kubernetes.io/docs/concepts/services-networking/ingress/#tls>
# e.g.
K8S_NAMESPACE="default"
TLS_CERT_DOMAIN="${K8S_NAMESPACE}.minikube.local"
kubectl --namespace "${K8S_NAMESPACE}" create secret tls defectdojo-tls \
  --key <(openssl rsa \
    -in "${CA_DIR}/private/${TLS_CERT_DOMAIN}.key.pem" \
    -passin "pass:${TLS_CERT_PASSWORD}") \
  --cert <(cat \
    "${CA_DIR}/certs/${TLS_CERT_DOMAIN}.cert.pem" \
    "${CA_DIR}/chain.pem")

# Install Helm chart. Choose a host name that matches the certificate above
helm install \
  ./helm/defectdojo \
  --name=defectdojo \
  --namespace="${K8S_NAMESPACE}" \
  --set host="defectdojo.${TLS_CERT_DOMAIN}"

# Navigate to https://defectdojo.minikube.local

# Uninstall Helm chart
helm delete defectdojo --purge
```

## Other useful stuff

```zsh
# View logs of a specific pod
kubectl logs $(kubectl get pod --selector=defectdojo.org/component=${POD} \
  -o jsonpath="{.items[0].metadata.name}") -f

# Open a shell in a specific pod
kubectl exec -it $(kubectl get pod --selector=defectdojo.org/component=${POD} \
  -o jsonpath="{.items[0].metadata.name}") -- /bin/bash

# Open a Python shell in a specific pod
kubectl exec -it $(kubectl get pod --selector=defectdojo.org/component=${POD} \
  -o jsonpath="{.items[0].metadata.name}") -- python manage.py shell
```

## Run in with plain Docker

The following describes how to run the docker images built above. This is not
intended for production use, but rather as a memo for creating a Helm chart.

```zsh
# Network
docker network create defectdojo

# MySQL
docker run --rm -it --network=defectdojo \
  --name=defectdojo_mysql \
  --network-alias mysql \
  --env MYSQL_DATABASE=defectdojo \
  --env MYSQL_USER=defectdojo \
  --env MYSQL_PASSWORD=defectdojo \
  --env MYSQL_RANDOM_ROOT_PASSWORD=pleaseChangeMe \
  mysql:5.7

# Django application
docker run --rm -it --network=defectdojo \
  --name=defectdojo_uwsgi \
  --network-alias uwsgi \
  --env DD_ALLOWED_HOSTS='*' \
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

# Navigate to http://localhost:8080
```
