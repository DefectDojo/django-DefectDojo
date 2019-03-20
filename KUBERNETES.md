# DefectDojo on Kubernetes

DefetDojo Kubernetes utilizes [Helm](https://helm.sh/), a
package manager for Kubernetes. Helm Charts help you define, install, and
upgrade even the most complex Kubernetes application.

For development purposes,
[minikube](https://kubernetes.io/docs/tasks/tools/install-minikube/)
and [Helm](https://helm.sh/) can be installed locally by following
this [guide](https://helm.sh/docs/using_helm/#installing-helm).

## Kubernetes Local Quickstart

Requirements:

1. Helm installed locally
2. Minikube installed locally
3. Latest cloned copy of DefectDojo

```zsh
git clone https://github.com/DefectDojo/django-DefectDojo
cd django-DefectDojo

minikube start
minikube addons enable ingress
helm init
helm repo update
helm dependency update ./helm/defectdojo
```

Now, install the helm chart into minikube:

```zsh
helm install \
  ./helm/defectdojo \
  --name=defectdojo \
  --set django.ingress.enabled=false
```

It usually takes up to a minute for the services to startup and the
status of the containers can be viewed by starting up ```minikube dashboard```.
Note: If the containers are not cached locally the services will start once the
containers have been pulled locally.

To be able to access DefectDojo, set up an ingress or access the service
directly by running the following command:

```zsh
kubectl port-forward --namespace=default \
service/defectdojo-django 8080:80
```

As you set your host value to defectdojo.default.minikube.local, make sure that
it resolves to the localhost IP address, e.g. by adding the following two lines
to /etc/hosts:

```zsh
::1       defectdojo.default.minikube.local
127.0.0.1 defectdojo.default.minikube.local
```

To find out the password, run the following command:

```zsh
echo "DefectDojo admin password: $(kubectl \
  get secret defectdojo \
  --namespace=default \
  --output jsonpath='{.data.DD_ADMIN_PASSWORD}' \
  | base64 --decode)"
```

To access DefectDojo, go to <http://defectdojo.default.minikube.local:8080>.
Log in with username admin and the password from the previous command.

### Minikube with locally built containers

If testing containers locally, then set the imagePullPolicy to Never,
which ensures containers are not pulled from Docker hub.

```zsh
helm install \
  ./helm/defectdojo \
  --name=defectdojo \
  --set django.ingress.enabled=false \
  --set imagePullPolicy=Never
```

### Build Images Locally

```zsh
# Build images
docker build -t defectdojo/defectdojo-django -f Dockerfile.django .
docker build -t defectdojo/defectdojo-nginx -f Dockerfile.nginx .
```

## Kubernetes Production

Optionally, for TLS locally, you need to install a TLS certificate into your
Kubernetes cluster.
For development purposes, you can create your own certificate authority as
described [here](https://github.com/hendrikhalkow/k8s-docs/blob/master/tls.md).

```zsh
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
```

```zsh
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

# Run highly available PostgreSQL cluster instead of MySQL - recommended setup
# for production environment.
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

# Note: If you run `helm install defectdojo before, you will get an error
# message like `Error: release defectdojo failed: secrets "defectdojo" already
# exists`. This is because the secret is kept across installations.
# To prevent recreating the secret, add --set createSecret=false` to your
# command.

# Run test. If there are any errors, re-run the command without `--cleanup` and
# inspect the test container.
helm test defectdojo --cleanup

# Navigate to <https://defectdojo.default.minikube.local>.
```

TODO: The MySQL volumes aren't persistent across `helm delete` operations. To
make them persistent, you need to add an annotation to the persistent volume
claim:

```zsh
kubectl --namespace "${K8S_NAMESPACE}" patch pvc defectdojo-mysql -p \
  '{"metadata": {"annotations": {"\"helm.sh/resource-policy\"": "keep"}}}'
```

See also
<https://github.com/helm/charts/blob/master/stable/mysql/templates/pvc.yaml>.

However, that doesn't work and I haven't found out why. In a production
environment, a redundant PostgreSQL cluster is the better option. As it uses
statefulsets that are kept by default, the problem doesn't exist there.

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
