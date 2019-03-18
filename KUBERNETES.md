# DefectDojo on Kubernetes

## Build images

```zsh
# Build images
docker build -t defectdojo/defectdojo-django -f Dockerfile.django .
docker build -t defectdojo/defectdojo-nginx -f Dockerfile.nginx .
```

## Run with Kubernetes

To install the Helm chart, you need to install a TLS certificate into your
Kubernetes cluster.
For development purposes, you can create your own certificate authority as
described [here](https://github.com/hendrikhalkow/k8s-docs/blob/master/tls.md).

```zsh
minikube start
minikube addons enable ingress
helm init
helm repo update
helm dependency update ./helm/defectdojo

# https://kubernetes.io/docs/concepts/services-networking/ingress/#tls
# Create a TLS secret called minikube-tls as mentioned above, e.g.
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
  --set host="defectdojo.${TLS_CERT_DOMAIN}" \
  --set django.ingress.secretName="minikube-tls"

# For high availability deploy multiple instances of Django, Celery and RabbitMQ
helm install \
  ./helm/defectdojo \
  --name=defectdojo \
  --namespace="${K8S_NAMESPACE}" \
  --set host="defectdojo.${TLS_CERT_DOMAIN}" \
  --set django.ingress.secretName="minikube-tls" \
  --set django.replicas=3 \
  --set celery.replicas=3 \
  --set rabbitmq.replicas=3

# Run highly available PostgreSQL cluster instead of MySQL
helm install \
  ./helm/defectdojo \
  --name=defectdojo \
  --namespace="${K8S_NAMESPACE}" \
  --set host="defectdojo.${TLS_CERT_DOMAIN}" \
  --set django.replicas=3 \
  --set celery.replicas=3 \
  --set rabbitmq.replicas=3 \
  --set django.ingress.secretName="minikube-tls" \
  --set mysql.enabled=false \
  --set database=postgresql \
  --set postgresql.enabled=true \
  --set postgresql.replication.enabled=true \
  --set postgresql.replication.slaveReplicas=3

# Run test. If there are any errors, re-run the command without `--cleanup` and
# inspect the test container.
helm test defectdojo --cleanup

# Navigate to <https://defectdojo.default.minikube.local>.
```

### Useful stuff

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

### Clean up Kubernetes

```zsh
# Uninstall Helm chart
helm delete defectdojo --purge
```

## Run with Docker Compose

Docker compose is not intended for production use.
If you want to deploy a containerized DefectDojo to a production environment,
use the Helm and Kubernetes approach described above.

### Setup via Docker Compose

```zsh
docker-compose up
```

### Clean up Docker Compose

```zsh
docker-compose down --volumes
```
