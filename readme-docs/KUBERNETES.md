# DefectDojo on Kubernetes

DefectDojo Kubernetes utilizes [Helm](https://helm.sh/), a
package manager for Kubernetes. Helm Charts help you define, install, and
upgrade even the most complex Kubernetes application.

For development purposes,
[minikube](https://kubernetes.io/docs/tasks/tools/install-minikube/)
and [Helm](https://helm.sh/) can be installed locally by following
this [guide](https://helm.sh/docs/using_helm/#installing-helm).

## Supported Kubernetes Versions
The tests cover the deployment on the lastest [kubernetes version](https://kubernetes.io/releases/) and the oldest supported [version from AWS](https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html#available-versions). The assumption is that version in between do not have significant differences. Current tested versions can looks up in the [github k8s workflow](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/k8s-testing.yml).

## Helm chart
Starting with version 1.14.0, a helm chart will be pushed onto the `helm-charts` branch during the release process. Don't look for a chart museum, we're leveraging the "raw" capabilities of GitHub at this time.

To use it, you can add our repo.

```
$ helm repo add helm-charts 'https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/helm-charts'
"helm-charts" has been added to your repositories

$ helm repo update
```

You should now be able to see the chart.

```
$ helm search repo defectdojo
NAME                      	CHART VERSION	APP VERSION	DESCRIPTION
helm-charts/defectdojo	    1.5.1        	1.14.0-dev 	A Helm chart for Kubernetes to install DefectDojo
```

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
```

Helm >= v3
```zsh
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update
```
Then pull the dependent charts:
```zsh
helm dependency update ./helm/defectdojo
```

Now, install the helm chart into minikube.

If you have setup an ingress controller:
```zsh
DJANGO_INGRESS_ENABLED=true
```
else:
```zsh
DJANGO_INGRESS_ENABLED=false
```

If you have configured TLS:
```zsh
DJANGO_INGRESS_ACTIVATE_TLS=true
```
else:
```zsh
DJANGO_INGRESS_ACTIVATE_TLS=false
```

Warning: Use the `createSecret*=true` flags only upon first install. For re-installs, see `§Re-install the chart`

Helm >= v3:

```zsh
helm install \
  defectdojo \
  ./helm/defectdojo \
  --set django.ingress.enabled=${DJANGO_INGRESS_ENABLED} \
  --set django.ingress.activateTLS=${DJANGO_INGRESS_ACTIVATE_TLS} \
  --set createSecret=true \
  --set createRabbitMqSecret=true \
  --set createRedisSecret=true \
  --set createMysqlSecret=true \
  --set createPostgresqlSecret=true
```
Note that you need only one of:
- postgresql or mysql
- rabbitmq or redis

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

Use the same commands as before but add:
```zsh
  --set imagePullPolicy=Never
```

### Installing from a private registry
If you have stored your images in a private registry, you can install defectdojo chart with (helm 3).

- First create a secret named "defectdojoregistrykey" based on the credentials that can pull from the registry: see https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/
- Then install the chart with the same commands as before but adding:
```zsh
  --set repositoryPrefix=<myregistry.com/path> \
  --set imagePullSecrets=defectdojoregistrykey
```

### Build Images Locally

```zsh
# Build images
docker build -t defectdojo/defectdojo-django -f Dockerfile.django .
docker build -t defectdojo/defectdojo-nginx -f Dockerfile.nginx .
```

```zsh
# Build images behind proxy
docker build --build-arg http_proxy=http://myproxy.com:8080 --build-arg https_proxy=http://myproxy.com:8080 -t defectdojo/defectdojo-django -f Dockerfile.django .
docker build --build-arg http_proxy=http://myproxy.com:8080 --build-arg https_proxy=http://myproxy.com:8080 -t defectdojo/defectdojo-nginx -f Dockerfile.nginx .
```

### Debug uWSGI with ptvsd

You can set breakpoints in code that is handled by uWSGI. The feature is meant to be used when you run locally on minikube, and mimics [what can be done with docker-compose](DOCKER.md#run-with-docker-compose-in-development-mode-with-ptvsd-remote-debug).

The port is currently hard-coded to 3000.

* In `values.yaml`, ensure the value for `enable_ptvsd` is set to `true` (the default is `false`). Make sure the change is taken into account in your deployment.
* Have `DD_DEBUG` set to `True`.
* Port forward port 3000 to the pod, such as `kubectl port-forward defectdojo-django-7886f49466-7cwm7 3000`.

### Upgrade the chart
If you want to change kubernetes configuration of use an updated docker image (evolution of defectDojo code), upgrade the application:
```
kubectl delete job defectdojo-initializer
helm upgrade  defectdojo ./helm/defectdojo/ \
   --set django.ingress.enabled=${DJANGO_INGRESS_ENABLED} \
   --set django.ingress.activateTLS=${DJANGO_INGRESS_ACTIVATE_TLS}
```


### Re-install the chart
In case of issue or in any other situation where you need to re-install the chart, you can do it and re-use the same secrets.

**Note that when using mysql, this will create a new database, while with postgresql you'll keep the same database (more information below)**

```zsh
# helm 3
helm uninstall defectdojo
helm install \
  defectdojo \
  ./helm/defectdojo \
  --set django.ingress.enabled=${DJANGO_INGRESS_ENABLED} \
  --set django.ingress.activateTLS=${DJANGO_INGRESS_ACTIVATE_TLS}
```

## Kubernetes Production

When running defectdojo in production be aware that you understood the full setup and always have a backup.

### Encryption to Kubernetes

Optionally, for TLS locally, you need to install a TLS certificate into your Kubernetes cluster.
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

### Encryption in Kubernetes and End-to-End Encryption

With the TLS certificate from your Kubernetes cluster all traffic to you cluster is encrypted, but the traffic in your cluster is still unencrypted.

If you want to encrypt the traffic to the nginx server you can use the option `--set nginx.tls.enabled=true` and `--set nginx.tls.generateCertificate=true` to generate a self signed certificate and use the https config. The option to add you own pregenerated certificate is generelly possible but not implemented in the helm chart yet.

Be aware that the traffic to the database and celery broker are unencrypted at the moment.


### Media persistent volume

By default, DefectDojo helm installation doesn't support persistent storage for storing images (dynamically uploaded by users). By default, it uses emptyDir, which is ephemeral by its nature and doesn't support multiple replicas of django pods, so should not be in use for production.

To enable persistence of the media storage that supports R/W many, should be in use as backend storage like S3, NFS, glusterfs, etc

```bash
mediaPersistentVolume:
  enabled: true
  # any name
  name: media
  # could be emptyDir (not for production) or pvc
  type: pvc
  # in case if pvc specified, should point to already existing pvc
  persistentVolumeClaim: media
```

In the example above, we want that media content to be preserved to `pvc` named `media` as `persistentVolumeClaim` k8s resource.

NOTE: PersistrentVolume needs to be prepared in front before helm installation/update is triggered.

For more detail how how to create proper PVC see [example](https://github.com/DefectDojo/Community-Contribs/tree/master/persistent-media)

### Installation

```zsh
# Install Helm chart. Choose a host name that matches the certificate above
helm install \
  defectdojo \
  ./helm/defectdojo \
  --namespace="${K8S_NAMESPACE}" \
  --set host="defectdojo.${TLS_CERT_DOMAIN}" \
  --set django.ingress.secretName="minikube-tls" \
  --set createSecret=true \
  --set createRabbitMqSecret=true \
  --set createRedisSecret=true \
  --set createMysqlSecret=true \
  --set createPostgresqlSecret=true

# For high availability deploy multiple instances of Django, Celery and RabbitMQ
helm install \
  defectdojo \
  ./helm/defectdojo \
  --namespace="${K8S_NAMESPACE}" \
  --set host="defectdojo.${TLS_CERT_DOMAIN}" \
  --set django.ingress.secretName="minikube-tls" \
  --set django.replicas=3 \
  --set celery.replicas=3 \
  --set rabbitmq.replicas=3 \
  --set createSecret=true \
  --set createRabbitMqSecret=true \
  --set createRedisSecret=true \
  --set createMysqlSecret=true \
  --set createPostgresqlSecret=true

# Run highly available PostgreSQL cluster instead of MySQL - recommended setup
# for production environment.
helm install \
  defectdojo \
  ./helm/defectdojo \
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
  --set postgresql.replication.slaveReplicas=3 \
  --set createSecret=true \
  --set createRabbitMqSecret=true \
  --set createRedisSecret=true \
  --set createMysqlSecret=true \
  --set createPostgresqlSecret=true

# Note: If you run `helm install defectdojo before, you will get an error
# message like `Error: release defectdojo failed: secrets "defectdojo" already
# exists`. This is because the secret is kept across installations.
# To prevent recreating the secret, add --set createSecret=false` to your
# command.

# Run test.
helm test defectdojo

# Navigate to <https://defectdojo.default.minikube.local>.
```

TODO: The MySQL volumes aren't persistent across `helm uninstall` operations. To
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

### Prometheus metrics

It's possible to enable Nginx prometheus exporter by setting `--set monitoring.enabled=true` and `--set monitoring.prometheus.enabled=true`. This adds the Nginx exporter sidecar and the standard Prometheus pod annotations to django deployment.

## Useful stuff

### Setting your own domain
The `site_url` in values.yaml controls what domain is configured in Django, and also what the celery workers will put as links in Jira tickets for example.
Set this to your `https://<yourdomain>` in values.yaml

### Multiple Hostnames
Django requires a list of all hostnames that are valid for requests.
You can add additional hostnames via helm or values file as an array.
This helps if you have a local service submitting reports to defectDojo using
the namespace name (say defectdojo.scans) instead of the TLD name used in a browser.

In your helm install simply pass them as a defined array, for example:

`--set "alternativeHosts={defectdojo.default,localhost,defectdojo.example.com}"`

This will also work with shell inserted variables:

` --set "alternativeHosts={defectdojo.${TLS_CERT_DOMAIN},localhost}"`

You will still need to set a host value as well.

### kubectl commands
```zsh
# View logs of a specific pod
kubectl logs $(kubectl get pod --selector=defectdojo.org/component=${POD} \
  -o jsonpath="{.items[0].metadata.name}") -f

# Open a shell in a specific pod
kubectl exec -it $(kubectl get pod --selector=defectdojo.org/component=${POD} \
  -o jsonpath="{.items[0].metadata.name}") -- /bin/bash
# Or:
kubectl exec defectdojo-django-<xxx-xxx> -c uwsgi -it /bin/sh

# Open a Python shell in a specific pod
kubectl exec -it $(kubectl get pod --selector=defectdojo.org/component=${POD} \
  -o jsonpath="{.items[0].metadata.name}") -- python manage.py shell
```

### Clean up Kubernetes
Helm >= v3
```
helm uninstall defectdojo
```

To remove persistent objects not removed by uninstall (this will remove any database):
```
kubectl delete secrets defectdojo defectdojo-redis-specific defectdojo-rabbitmq-specific defectdojo-postgresql-specific defectdojo-mysql-specific
kubectl delete serviceAccount defectdojo
kubectl delete pvc data-defectdojo-rabbitmq-0 data-defectdojo-postgresql-0 data-defectdojo-mysql-0
```
