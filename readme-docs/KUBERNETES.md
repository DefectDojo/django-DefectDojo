# DefectDojo on Kubernetes

DefectDojo Kubernetes utilizes [Helm](https://helm.sh/), a
package manager for Kubernetes. Helm Charts help you define, install, and
upgrade even the most complex Kubernetes application.

For development purposes,
[minikube](https://kubernetes.io/docs/tasks/tools/install-minikube/)
and [Helm](https://helm.sh/) can be installed locally by following
this [guide](https://helm.sh/docs/using_helm/#installing-helm).

## Supported Kubernetes Versions

The tests cover the deployment on the lastest [kubernetes version](https://kubernetes.io/releases/) and the oldest supported [version from AWS](https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html#available-versions). The assumption is that version in between do not have significant differences. Current tested versions can looks up in the [github k8s workflow](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/k8s-tests.yml).

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
  --set createRedisSecret=true \
  --set createPostgresqlSecret=true
```

It usually takes up to a minute for the services to startup and the
status of the containers can be viewed by starting up `minikube dashboard`.
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

**Note: With postgresql you'll keep the same database (more information below)**

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
  # there are two options to create pvc 1) when you want the chart to create pvc for you, set django.mediaPersistentVolume.persistentVolumeClaim.create to true and do not specify anything for django.mediaPersistentVolume.PersistentVolumeClaim.name  2) when you want to create pvc outside the chart, pass the pvc name via django.mediaPersistentVolume.PersistentVolumeClaim.name and ensure django.mediaPersistentVolume.PersistentVolumeClaim.create is set to false
  persistentVolumeClaim:
    create: true
    name:
    size: 5Gi
    accessModes:
    - ReadWriteMany
    storageClassName:
```

In the example above, we want the media content to be preserved to `pvc` as `persistentVolumeClaim` k8s resource and what we are basically doing is enabling the pvc to be created conditionally if the user wants to create it using the chart (in this case the pvc name 'defectdojo-media' will be inherited from template file used to deploy the pvc). By default the volume type is emptyDir which does not require a pvc. But when the type is set to pvc then we need a kubernetes Persistent Volume Claim and this is where the django.mediaPersistentVolume.persistentVolumeClaim.name comes into play.

The accessMode is set to ReadWriteMany by default to accommodate using more than one replica. Ensure storage support ReadWriteMany before setting this option, otherwise set accessMode to ReadWriteOnce.

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
  --set createRedisSecret=true \
  --set createPostgresqlSecret=true

# For high availability deploy multiple instances of Django, Celery and Redis
helm install \
  defectdojo \
  ./helm/defectdojo \
  --namespace="${K8S_NAMESPACE}" \
  --set host="defectdojo.${TLS_CERT_DOMAIN}" \
  --set django.ingress.secretName="minikube-tls" \
  --set django.replicas=3 \
  --set celery.worker.replicas=3 \
  --set redis.replicas=3 \
  --set createSecret=true \
  --set createRedisSecret=true \
  --set createPostgresqlSecret=true

# Run highly available PostgreSQL cluster
# for production environment.
helm install \
  defectdojo \
  ./helm/defectdojo \
  --namespace="${K8S_NAMESPACE}" \
  --set host="defectdojo.${TLS_CERT_DOMAIN}" \
  --set django.replicas=3 \
  --set celery.worker.replicas=3 \
  --set redis.replicas=3 \
  --set django.ingress.secretName="minikube-tls" \
  --set database=postgresql \
  --set postgresql.enabled=true \
  --set postgresql.replication.enabled=true \
  --set postgresql.replication.slaveReplicas=3 \
  --set createSecret=true \
  --set createRedisSecret=true \
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

### Prometheus metrics

It's possible to enable Nginx prometheus exporter by setting `--set monitoring.enabled=true` and `--set monitoring.prometheus.enabled=true`. This adds the Nginx exporter sidecar and the standard Prometheus pod annotations to django deployment.

## Useful stuff

### Setting your own domain

The `siteUrl` in values.yaml controls what domain is configured in Django, and also what the celery workers will put as links in Jira tickets for example.
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

### Using an existing redis setup with redis-sentinel

If you want to use a redis-sentinel setup as the Celery broker, you will need to set the following.

1. Set redis.scheme to "sentinel" in values.yaml
2. Set two additional extraEnv vars specifying the sentinel master name and port in values.yaml

```yaml
celery:
  broker: 'redis'

redis:
  redisServer: 'PutYourRedisSentinelAddress'
  scheme: 'sentinel'

extraEnv:
  - name: DD_CELERY_BROKER_TRANSPORT_OPTIONS
    value: '{"master_name": "mymaster"}'
  - name: 'DD_CELERY_BROKER_PORT'
    value: '26379'
```


### How to use an external PostgreSQL DB with Defectdojo

#### Step 1: Create a Namespace for DefectDojo

To begin, create a dedicated namespace for DefectDojo to isolate its resources:
`kubectl create ns defectdojo`
#### Step 2: Create a Secret for PostgreSQL Credentials

Set up a Kubernetes Secret to securely store the PostgreSQL user password and database connection URL, which are essential for establishing a secure connection between DefectDojo and your PostgreSQL instance. Apply the secret using the following command: `kubectl apply -f secret.yaml -n defectdojo`. This secret will be referenced within the `extraEnv` section of the DefectDojo Helm values file.

Sample secret template (replace the placeholders with your PostgreSQL credentials):
```YAML
apiversion: v1
kind: Secret
metadata:  
  name: defectdojo-postgresql-specific  
type: Opaque
stringData:  # I chose stringData for better visualization of the credentials for debugging
  postgresql-password: <user-password>
  db-url: psql://<username>:<password>@<hostname>:<port>/<database-name> 
```

#### Step 2.5: Install PostgreSQL (Optional)

If you need to simulate a PostgreSQL database external to DefectDojo, you can install PostgreSQL using the following Helm command:

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami 
helm repo update
helm install defectdojo-postgresql bitnami/postgresql -n defectdojo -f postgresql/values.yaml
```


Sample `values.yaml` file for PostgreSQL configuration:

```YAML 
auth:
  username: defectdojo
  password: <user-password>
  postgresPassword: <admin-password>
  database: defectdojo
  primary:
    persistence:
    size: 10Gi
```

#### Step 3: Modify DefectDojo helm values

Before installing the DefectDojo Helm chart, it's important to customize the `values.yaml` file. Key areas to modify include specifying the PostgreSQL connection details & the extraEnv block:

```yaml
database: postgresql
postgresql:
  postgresServer: "defectdojo-postgresql" # point to the hostname of your postgresql server
  enabled: false

# Specify the postgresql DB connection url for the external postgresql server
extraEnv:
  - name: DD_DATABASE_URL
    valueFrom:
      secretKeyRef:
        name: defectdojo-postgresql-specific
        key: db-url
```

#### Step 4: Deploy DefectDojo

After modifying the `values.yaml` file as needed, deploy DefectDojo using Helm. This command also generates the required secrets for the DefectDojo admin UI and Redis:

```bash
helm install defectdojo defectdojo -f values.yaml -n defectdojo --set createSecret=true --set createRedisSecret=true
```


**NOTE**: It is important to highlight that this setup can also be utilized for achieving high availability (HA) in PostgreSQL. By placing a load balancer in front of the PostgreSQL cluster, read and write requests can be efficiently routed to the appropriate primary or standby servers as needed.


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
kubectl delete secrets defectdojo defectdojo-redis-specific defectdojo-postgresql-specific
kubectl delete serviceAccount defectdojo
kubectl delete pvc data-defectdojo-redis-0 data-defectdojo-postgresql-0
```
