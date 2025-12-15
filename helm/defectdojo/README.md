# DefectDojo on Kubernetes

DefectDojo Kubernetes utilizes [Helm](https://helm.sh/), a
package manager for Kubernetes. Helm Charts help you define, install, and
upgrade even the most complex Kubernetes application.

For development purposes,
[minikube](https://kubernetes.io/docs/tasks/tools/install-minikube/)
and [Helm](https://helm.sh/) can be installed locally by following
this [guide](https://helm.sh/docs/using_helm/#installing-helm).

## Supported Kubernetes Versions

The tests cover the deployment on the lastest [kubernetes version](https://kubernetes.io/releases/) and [the oldest officially supported version](https://kubernetes.io/releases/). The assumption is that version in between do not have significant differences. Current tested versions can looks up in the [github k8s workflow](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/k8s-tests.yml).

## Helm chart

Starting with version 1.14.0, a helm chart will be pushed onto the `helm-charts` branch during the release process. Don't look for a chart museum, we're leveraging the "raw" capabilities of GitHub at this time.

To use it, you can add our repo.

```
$ helm repo add defectdojo 'https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/helm-charts'

$ helm repo update
```

You should now be able to see the chart.

```
$ helm search repo defectdojo
NAME                      	CHART VERSION	APP VERSION	DESCRIPTION
defectdojo/defectdojo   1.6.153         2.39.0          A Helm chart for Kubernetes to install DefectDojo
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
  --set createValkeySecret=true \
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

**Important:** If you choose to create the secret on your own, you will need to create a secret named `defectdojo` and containing the following fields:

- DD_ADMIN_PASSWORD
- DD_SECRET_KEY
- DD_CREDENTIAL_AES_256_KEY
- METRICS_HTTP_AUTH_PASSWORD

Theses fields are required to get the stack running.

```zsh
# Install Helm chart. Choose a host name that matches the certificate above
helm install \
  defectdojo \
  ./helm/defectdojo \
  --namespace="${K8S_NAMESPACE}" \
  --set host="defectdojo.${TLS_CERT_DOMAIN}" \
  --set django.ingress.secretName="minikube-tls" \
  --set createSecret=true \
  --set createValkeySecret=true \
  --set createPostgresqlSecret=true

# For high availability deploy multiple instances of Django, Celery and Valkey
helm install \
  defectdojo \
  ./helm/defectdojo \
  --namespace="${K8S_NAMESPACE}" \
  --set host="defectdojo.${TLS_CERT_DOMAIN}" \
  --set django.ingress.secretName="minikube-tls" \
  --set django.replicas=3 \
  --set celery.worker.replicas=3 \
  --set valkey.architecture=replication \
  --set valkey.replicaCount=3 \
  --set createSecret=true \
  --set createValkeySecret=true \
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
  --set valkey.architecture=replication \
  --set valkey.replicaCount=3 \
  --set django.ingress.secretName="minikube-tls" \
  --set postgresql.enabled=true \
  --set postgresql.replication.enabled=true \
  --set postgresql.replication.slaveReplicas=3 \
  --set createSecret=true \
  --set createValkeySecret=true \
  --set createPostgresqlSecret=true

# Note: If you run `helm install defectdojo before, you will get an error
# message like `Error: release defectdojo failed: secrets "defectdojo" already
# exists`. This is because the secret is kept across installations.
# To prevent recreating the secret, add --set createSecret=false` to your
# command.

# Run test.
helm test defectdojo

# Navigate to <YOUR_INGRESS_ENDPOINT>.
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

`--set "alternativeHosts={defectdojo.${TLS_CERT_DOMAIN},localhost}"`

You will still need to set a host value as well.

### Using an existing redis setup with redis-sentinel

If you want to use a redis-sentinel setup as the Celery broker, you will need to set the following.

1. Set valkey.scheme to "sentinel" in values.yaml
2. Set two additional extraEnv vars specifying the sentinel master name and port in values.yaml

```yaml
valkey:
  scheme: 'sentinel'
redisServer: 'PutYourRedisSentinelAddress'

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
  password: <user-password>
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
postgresql:
  enabled: false # Disable the creation of the database in the cluster
  postgresServer: "127.0.0.1" # Required to skip certain tests not useful on external instances
  auth:
    username: defectdojo # your database user
    database: defectdojo # your database name
    secretKeys:
      adminPasswordKey: password # the name of the field containing the password value
      userPasswordKey: password # the name of the field containing the password value
      replicationPasswordKey: password # the name of the field containing the password value
    existingSecret: defectdojo-postgresql-specific # the secret containing your database password

extraEnv:
# Overwrite the database endpoint
- name: DD_DATABASE_HOST
  value: <YOUR_POSTGRES_HOST>
# Overwrite the database port
- name: DD_DATABASE_PORT
  value: <YOUR_POSTGRES_PORT>
```

#### Step 4: Deploy DefectDojo

After modifying the `values.yaml` file as needed, deploy DefectDojo using Helm. This command also generates the required secrets for the DefectDojo admin UI and Valkey:

```bash
helm install defectdojo defectdojo -f values.yaml -n defectdojo --set createSecret=true --set createValkeySecret=true
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

## Development/contribution

In case you decide to help with the improvement of the HELM chart, keep in mind that values/descriptions might need to be adjusted in multiple places (see below).

### HELM Docs update

Documentation provided in the README file needs to contain the latest information from `values.yaml` and all other related assets.
If GitHub Action _Lint Helm chart / Update documentation_ step fails, install https://github.com/norwoodj/helm-docs and run locally `helm-docs --chart-search-root helm/deeefectdojo` before committing your changes.
The helm-docs documentation will be generated for you.
     
### HELM Schema update

The HELM structure supports the existence of a `values.schema.json` file. This file is used to validate all values provided by the user before Helm starts rendering templates.
The chart needs to have a `values.schema.json` file that is compatible with the default `values.yaml` file.
If GitHub Action _Lint Helm chart / Update schema_ step fails, install https://github.com/losisin/helm-values-schema-json and run locally `helm schema --use-helm-docs` in `helm/defectdojo` before committing your changes.
The HELM schema will be generated for you.

# General information about chart values

![Version: 1.9.4-dev](https://img.shields.io/badge/Version-1.9.4--dev-informational?style=flat-square) ![AppVersion: 2.54.0-dev](https://img.shields.io/badge/AppVersion-2.54.0--dev-informational?style=flat-square)

A Helm chart for Kubernetes to install DefectDojo

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| madchap | <defectdojo-project@owasp.org> | <https://github.com/DefectDojo/django-DefectDojo> |

## Requirements

| Repository | Name | Version |
|------------|------|---------|
| oci://registry-1.docker.io/cloudpirates | valkey | 0.10.2 |
| oci://us-docker.pkg.dev/os-public-container-registry/defectdojo | postgresql | 16.7.27 |

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| admin.credentialAes256Key | string | `""` |  |
| admin.firstName | string | `"Administrator"` |  |
| admin.lastName | string | `"User"` |  |
| admin.mail | string | `"admin@defectdojo.local"` |  |
| admin.metricsHttpAuthPassword | string | `""` |  |
| admin.password | string | `""` |  |
| admin.secretKey | string | `""` |  |
| admin.user | string | `"admin"` |  |
| alternativeHosts | list | `[]` | optional list of alternative hostnames to use that gets appended to DD_ALLOWED_HOSTS. This is necessary when your local hostname does not match the global hostname. |
| celery.annotations | object | `{}` | Common annotations to worker and beat deployments and pods. |
| celery.beat.affinity | object | `{}` |  |
| celery.beat.annotations | object | `{}` | Annotations for the Celery beat deployment. |
| celery.beat.automountServiceAccountToken | bool | `false` |  |
| celery.beat.containerSecurityContext | object | `{}` | Container security context for the Celery beat containers. |
| celery.beat.extraEnv | list | `[]` | Additional environment variables injected to Celery beat containers. |
| celery.beat.extraInitContainers | list | `[]` | A list of additional initContainers to run before celery beat containers. |
| celery.beat.extraVolumeMounts | list | `[]` | Array of additional volume mount points for the celery beat containers. |
| celery.beat.extraVolumes | list | `[]` | A list of extra volumes to mount @type: array<map> |
| celery.beat.image | object | `{"digest":"","registry":"","repository":"","tag":""}` | If empty, uses values from images.django.image |
| celery.beat.livenessProbe | object | `{}` | Enable liveness probe for Celery beat container. ``` exec:   command:     - bash     - -c     - celery -A dojo inspect ping -t 5 initialDelaySeconds: 30 periodSeconds: 60 timeoutSeconds: 10 ``` |
| celery.beat.nodeSelector | object | `{}` |  |
| celery.beat.podAnnotations | object | `{}` | Annotations for the Celery beat pods. |
| celery.beat.podSecurityContext | object | `{}` | Pod security context for the Celery beat pods. |
| celery.beat.readinessProbe | object | `{}` | Enable readiness probe for Celery beat container. |
| celery.beat.replicas | int | `1` | Multiple replicas are not allowed (Beat is intended to be a singleton) because scaling to >1 will double-run schedules |
| celery.beat.resources.limits.cpu | string | `"2000m"` |  |
| celery.beat.resources.limits.memory | string | `"256Mi"` |  |
| celery.beat.resources.requests.cpu | string | `"100m"` |  |
| celery.beat.resources.requests.memory | string | `"128Mi"` |  |
| celery.beat.startupProbe | object | `{}` | Enable startup probe for Celery beat container. |
| celery.beat.tolerations | list | `[]` |  |
| celery.logLevel | string | `"INFO"` |  |
| celery.worker.affinity | object | `{}` |  |
| celery.worker.annotations | object | `{}` | Annotations for the Celery worker deployment. |
| celery.worker.appSettings.poolType | string | `"solo"` | Performance improved celery worker config when needing to deal with a lot of findings (e.g deduplication ops) poolType: prefork autoscaleMin: 2 autoscaleMax: 8 concurrency: 8 prefetchMultiplier: 128 |
| celery.worker.automountServiceAccountToken | bool | `false` |  |
| celery.worker.autoscaling | object | `{"behavior":{},"enabled":false,"maxReplicas":5,"minReplicas":2,"targetCPUUtilizationPercentage":80,"targetMemoryUtilizationPercentage":80}` | Autoscaling configuration for Celery worker deployment. |
| celery.worker.containerSecurityContext | object | `{}` | Container security context for the Celery worker containers. |
| celery.worker.extraEnv | list | `[]` | Additional environment variables injected to Celery worker containers. |
| celery.worker.extraInitContainers | list | `[]` | A list of additional initContainers to run before celery worker containers. |
| celery.worker.extraVolumeMounts | list | `[]` | Array of additional volume mount points for the celery worker containers. |
| celery.worker.extraVolumes | list | `[]` | A list of extra volumes to mount. @type: array<map> |
| celery.worker.image | object | `{"digest":"","registry":"","repository":"","tag":""}` | If empty, uses values from images.django.image |
| celery.worker.livenessProbe | object | `{}` | Enable liveness probe for Celery worker containers. ``` exec:   command:     - bash     - -c     - celery -A dojo inspect ping -t 5 initialDelaySeconds: 30 periodSeconds: 60 timeoutSeconds: 10 ``` |
| celery.worker.nodeSelector | object | `{}` |  |
| celery.worker.podAnnotations | object | `{}` | Annotations for the Celery worker pods. |
| celery.worker.podDisruptionBudget | object | `{"enabled":false,"minAvailable":"50%","unhealthyPodEvictionPolicy":"AlwaysAllow"}` | Configure pod disruption budgets for Celery worker ref: https://kubernetes.io/docs/tasks/run-application/configure-pdb/#specifying-a-poddisruptionbudget |
| celery.worker.podSecurityContext | object | `{}` | Pod security context for the Celery worker pods. |
| celery.worker.readinessProbe | object | `{}` | Enable readiness probe for Celery worker container. |
| celery.worker.replicas | int | `1` |  |
| celery.worker.resources.limits.cpu | string | `"2000m"` |  |
| celery.worker.resources.limits.memory | string | `"512Mi"` |  |
| celery.worker.resources.requests.cpu | string | `"100m"` |  |
| celery.worker.resources.requests.memory | string | `"128Mi"` |  |
| celery.worker.startupProbe | object | `{}` | Enable startup probe for Celery worker container. |
| celery.worker.terminationGracePeriodSeconds | int | `300` |  |
| celery.worker.tolerations | list | `[]` |  |
| cloudsql | object | `{"containerSecurityContext":{},"enable_iam_login":false,"enabled":false,"extraEnv":[],"extraVolumeMounts":[],"image":{"pullPolicy":"IfNotPresent","repository":"gcr.io/cloudsql-docker/gce-proxy","tag":"1.37.10"},"instance":"","resources":{},"use_private_ip":false,"verbose":true}` | Google CloudSQL support in GKE via gce-proxy |
| cloudsql.containerSecurityContext | object | `{}` | Optional: security context for the CloudSQL proxy container. |
| cloudsql.enable_iam_login | bool | `false` | use IAM database authentication |
| cloudsql.enabled | bool | `false` | To use CloudSQL in GKE set 'enable: true' |
| cloudsql.extraEnv | list | `[]` | Additional environment variables for the CloudSQL proxy container. |
| cloudsql.extraVolumeMounts | list | `[]` | Array of additional volume mount points for the CloudSQL proxy container |
| cloudsql.image | object | `{"pullPolicy":"IfNotPresent","repository":"gcr.io/cloudsql-docker/gce-proxy","tag":"1.37.10"}` | set repo and image tag of gce-proxy |
| cloudsql.instance | string | `""` | set CloudSQL instance: 'project:zone:instancename' |
| cloudsql.resources | object | `{}` | Optional: add resource requests/limits for the CloudSQL proxy container. |
| cloudsql.use_private_ip | bool | `false` | whether to use a private IP to connect to the database |
| cloudsql.verbose | bool | `true` | By default, the proxy has verbose logging. Set this to false to make it less verbose |
| createPostgresqlSecret | bool | `false` | create postgresql secret in defectdojo chart, outside of postgresql chart |
| createSecret | bool | `false` | create defectdojo specific secret |
| createValkeySecret | bool | `false` | create valkey secret in defectdojo chart, outside of valkey chart |
| dbMigrationChecker.containerSecurityContext | object | `{}` | Container security context for the DB migration checker. |
| dbMigrationChecker.enabled | bool | `true` | Enable/disable the DB migration checker. |
| dbMigrationChecker.extraEnv | list | `[]` | Additional environment variables for DB migration checker. |
| dbMigrationChecker.extraVolumeMounts | list | `[]` | Array of additional volume mount points for DB migration checker. |
| dbMigrationChecker.image | object | `{"digest":"","registry":"","repository":"","tag":""}` | If empty, uses values from images.django.image |
| dbMigrationChecker.resources | object | `{"limits":{"cpu":"200m","memory":"200Mi"},"requests":{"cpu":"100m","memory":"100Mi"}}` | Resource requests/limits for the DB migration checker. |
| disableHooks | bool | `false` | Avoid using pre-install hooks, which might cause issues with ArgoCD |
| django.affinity | object | `{}` |  |
| django.annotations | object | `{}` |  |
| django.automountServiceAccountToken | bool | `false` |  |
| django.autoscaling | object | `{"behavior":{},"enabled":false,"maxReplicas":5,"minReplicas":2,"targetCPUUtilizationPercentage":80,"targetMemoryUtilizationPercentage":80}` | Autoscaling configuration for the Django deployment. |
| django.extraEnv | list | `[]` | Additional environment variables injected to all Django containers and initContainers. |
| django.extraInitContainers | list | `[]` | A list of additional initContainers to run before the uwsgi and nginx containers. |
| django.extraVolumeMounts | list | `[]` | Array of additional volume mount points common to all containers and initContainers. |
| django.extraVolumes | list | `[]` | A list of extra volumes to mount. |
| django.ingress.activateTLS | bool | `true` |  |
| django.ingress.annotations | object | `{}` | Restricts the type of ingress controller that can interact with our chart (nginx, traefik, ...) `kubernetes.io/ingress.class: nginx` Depending on the size and complexity of your scans, you might want to increase the default ingress timeouts if you see repeated 504 Gateway Timeouts `nginx.ingress.kubernetes.io/proxy-read-timeout: "1800"` `nginx.ingress.kubernetes.io/proxy-send-timeout: "1800"` |
| django.ingress.enabled | bool | `true` |  |
| django.ingress.ingressClassName | string | `""` |  |
| django.ingress.secretName | string | `"defectdojo-tls"` |  |
| django.mediaPersistentVolume | object | `{"enabled":true,"name":"media","persistentVolumeClaim":{"accessModes":["ReadWriteMany"],"create":false,"name":"","size":"5Gi","storageClassName":""},"type":"emptyDir"}` | This feature needs more preparation before can be enabled, please visit KUBERNETES.md#media-persistent-volume |
| django.mediaPersistentVolume.name | string | `"media"` | any name |
| django.mediaPersistentVolume.persistentVolumeClaim | object | `{"accessModes":["ReadWriteMany"],"create":false,"name":"","size":"5Gi","storageClassName":""}` | in case if pvc specified, should point to the already existing pvc |
| django.mediaPersistentVolume.persistentVolumeClaim.accessModes | list | `["ReadWriteMany"]` | check KUBERNETES.md doc first for option to choose |
| django.mediaPersistentVolume.persistentVolumeClaim.create | bool | `false` | set to true to create a new pvc and if django.mediaPersistentVolume.type is set to pvc |
| django.mediaPersistentVolume.type | string | `"emptyDir"` | could be emptyDir (not for production) or pvc |
| django.nginx.containerSecurityContext | object | `{"runAsUser":1001}` | Container security context for the nginx containers. |
| django.nginx.containerSecurityContext.runAsUser | int | `1001` | nginx dockerfile sets USER=1001 |
| django.nginx.extraEnv | list | `[]` | To extra environment variables to the nginx container, you can use extraEnv. For example: extraEnv: - name: FOO   valueFrom:     configMapKeyRef:       name: foo       key: bar |
| django.nginx.extraVolumeMounts | list | `[]` | Array of additional volume mount points for nginx containers. |
| django.nginx.image | object | `{"digest":"","registry":"","repository":"","tag":""}` | If empty, uses values from images.nginx.image |
| django.nginx.resources.limits.cpu | string | `"2000m"` |  |
| django.nginx.resources.limits.memory | string | `"256Mi"` |  |
| django.nginx.resources.requests.cpu | string | `"100m"` |  |
| django.nginx.resources.requests.memory | string | `"128Mi"` |  |
| django.nginx.tls.enabled | bool | `false` |  |
| django.nginx.tls.generateCertificate | bool | `false` |  |
| django.nodeSelector | object | `{}` |  |
| django.podDisruptionBudget | object | `{"enabled":false,"minAvailable":"50%","unhealthyPodEvictionPolicy":"AlwaysAllow"}` | Configure pod disruption budgets for django ref: https://kubernetes.io/docs/tasks/run-application/configure-pdb/#specifying-a-poddisruptionbudget |
| django.podSecurityContext | object | `{"fsGroup":1001}` | Pod security context for the Django pods. |
| django.replicas | int | `1` |  |
| django.service.annotations | object | `{}` |  |
| django.service.type | string | `""` |  |
| django.strategy | object | `{}` |  |
| django.terminationGracePeriodSeconds | int | `60` |  |
| django.tolerations | list | `[]` |  |
| django.uwsgi.appSettings.maxFd | int | `0` | Use this value to set the maximum number of file descriptors. If set to 0 will be detected by uwsgi e.g. 102400 |
| django.uwsgi.appSettings.processes | int | `4` |  |
| django.uwsgi.appSettings.threads | int | `4` |  |
| django.uwsgi.certificates.certFileName | string | `"ca.crt"` |  |
| django.uwsgi.certificates.certMountPath | string | `"/certs/"` |  |
| django.uwsgi.certificates.configName | string | `"defectdojo-ca-certs"` |  |
| django.uwsgi.certificates.enabled | bool | `false` | includes additional CA certificate as volume, it refrences REQUESTS_CA_BUNDLE env varible to create configMap `kubectl create cm defectdojo-ca-certs --from-file=ca.crt` NOTE: it reflects REQUESTS_CA_BUNDLE for celery workers, beats as well |
| django.uwsgi.containerSecurityContext.runAsUser | int | `1001` | django dockerfile sets USER=1001 |
| django.uwsgi.enableDebug | bool | `false` | this also requires DD_DEBUG to be set to True |
| django.uwsgi.extraEnv | list | `[]` | To add (or override) extra variables which need to be pulled from another configMap, you can use extraEnv. For example: extraEnv: - name: DD_DATABASE_HOST   valueFrom:     configMapKeyRef:       name: my-other-postgres-configmap       key: cluster_endpoint |
| django.uwsgi.extraVolumeMounts | list | `[]` | Array of additional volume mount points for uwsgi containers. |
| django.uwsgi.image | object | `{"digest":"","registry":"","repository":"","tag":""}` | If empty, uses values from images.django.image |
| django.uwsgi.livenessProbe.enabled | bool | `true` | Enable liveness checks on uwsgi container. |
| django.uwsgi.livenessProbe.failureThreshold | int | `6` |  |
| django.uwsgi.livenessProbe.initialDelaySeconds | int | `0` |  |
| django.uwsgi.livenessProbe.periodSeconds | int | `10` |  |
| django.uwsgi.livenessProbe.successThreshold | int | `1` |  |
| django.uwsgi.livenessProbe.timeoutSeconds | int | `5` |  |
| django.uwsgi.readinessProbe.enabled | bool | `true` | Enable readiness checks on uwsgi container. |
| django.uwsgi.readinessProbe.failureThreshold | int | `6` |  |
| django.uwsgi.readinessProbe.initialDelaySeconds | int | `0` |  |
| django.uwsgi.readinessProbe.periodSeconds | int | `10` |  |
| django.uwsgi.readinessProbe.successThreshold | int | `1` |  |
| django.uwsgi.readinessProbe.timeoutSeconds | int | `5` |  |
| django.uwsgi.resources.limits.cpu | string | `"2000m"` |  |
| django.uwsgi.resources.limits.memory | string | `"512Mi"` |  |
| django.uwsgi.resources.requests.cpu | string | `"100m"` |  |
| django.uwsgi.resources.requests.memory | string | `"256Mi"` |  |
| django.uwsgi.startupProbe.enabled | bool | `true` | Enable startup checks on uwsgi container. |
| django.uwsgi.startupProbe.failureThreshold | int | `30` |  |
| django.uwsgi.startupProbe.initialDelaySeconds | int | `0` |  |
| django.uwsgi.startupProbe.periodSeconds | int | `5` |  |
| django.uwsgi.startupProbe.successThreshold | int | `1` |  |
| django.uwsgi.startupProbe.timeoutSeconds | int | `1` |  |
| extraAnnotations | object | `{}` | Annotations globally added to all resources |
| extraConfigs | object | `{}` | To add extra variables not predefined by helm config it is possible to define in extraConfigs block, e.g. below: NOTE  Do not store any kind of sensitive information inside of it ``` DD_SOCIAL_AUTH_AUTH0_OAUTH2_ENABLED: 'true' DD_SOCIAL_AUTH_AUTH0_KEY: 'dev' DD_SOCIAL_AUTH_AUTH0_DOMAIN: 'xxxxx' ``` |
| extraEnv | list | `[]` | To add (or override) extra variables which need to be pulled from another configMap, you can use extraEnv. For example: ``` - name: DD_DATABASE_HOST   valueFrom:     configMapKeyRef:       name: my-other-postgres-configmap       key: cluster_endpoint ``` |
| extraLabels | object | `{}` | Labels globally added to all resources |
| extraSecrets | object | `{}` | Extra secrets can be created inside of extraSecrets block: NOTE  This is just an exmaple, do not store sensitive data in plain text form, better inject it during the deployment/upgrade by --set extraSecrets.secret=someSecret ``` DD_SOCIAL_AUTH_AUTH0_SECRET: 'xxx' ``` |
| gke | object | `{"useGKEIngress":false,"useManagedCertificate":false,"workloadIdentityEmail":""}` | Settings to make running the chart on GKE simpler |
| gke.useGKEIngress | bool | `false` | Set to true to configure the Ingress to use the GKE provided ingress controller |
| gke.useManagedCertificate | bool | `false` | Set to true to have GKE automatically provision a TLS certificate for the host specified Requires useGKEIngress to be set to true When using this option, be sure to set django.ingress.activateTLS to false |
| gke.workloadIdentityEmail | string | `""` | Workload Identity allows the K8s service account to assume the IAM access of a GCP service account to interact with other GCP services Only works with serviceAccount.create = true |
| host | string | `"defectdojo.default.minikube.local"` | Primary hostname of instance |
| imagePullPolicy | string | `"Always"` |  |
| imagePullSecrets | string | `nil` | When using a private registry, name of the secret that holds the registry secret (eg deploy token from gitlab-ci project) Create secrets as: kubectl create secret docker-registry defectdojoregistrykey --docker-username=registry_username --docker-password=registry_password --docker-server='https://index.docker.io/v1/' |
| images.django.image.digest | string | `""` | Prefix "sha256:" is expected in this place |
| images.django.image.registry | string | `""` |  |
| images.django.image.repository | string | `"defectdojo/defectdojo-django"` |  |
| images.django.image.tag | string | `""` | If empty, use appVersion. Another possible values are: latest, X.X.X, X.X.X-debian, X.X.X-alpine (where X.X.X is version of DD). For dev builds (only for testing purposes): nightly-dev, nightly-dev-debian, nightly-dev-alpine. To see all, check https://hub.docker.com/r/defectdojo/defectdojo-django/tags. |
| images.nginx.image.digest | string | `""` | Prefix "sha256:" is expected in this place |
| images.nginx.image.registry | string | `""` |  |
| images.nginx.image.repository | string | `"defectdojo/defectdojo-nginx"` |  |
| images.nginx.image.tag | string | `""` | If empty, use appVersion. Another possible values are: latest, X.X.X, X.X.X-alpine (where X.X.X is version of DD). For dev builds (only for testing purposes): nightly-dev, nightly-dev-alpine. To see all, check https://hub.docker.com/r/defectdojo/defectdojo-nginx/tags. |
| initializer.affinity | object | `{}` |  |
| initializer.automountServiceAccountToken | bool | `false` |  |
| initializer.containerSecurityContext | object | `{}` | Container security context for the initializer Job container |
| initializer.extraEnv | list | `[]` | Additional environment variables injected to the initializer job pods. |
| initializer.extraVolumeMounts | list | `[]` | Array of additional volume mount points for the initializer job (init)containers. |
| initializer.extraVolumes | list | `[]` | A list of extra volumes to attach to the initializer job pods. |
| initializer.image | object | `{"digest":"","registry":"","repository":"","tag":""}` | If empty, uses values from images.django.image |
| initializer.jobAnnotations | object | `{}` |  |
| initializer.keepSeconds | int | `60` | A positive integer will keep this Job and Pod deployed for the specified number of seconds, after which they will be removed. For all other values, the Job and Pod will remain deployed. |
| initializer.labels | object | `{}` |  |
| initializer.nodeSelector | object | `{}` |  |
| initializer.podAnnotations | object | `{}` |  |
| initializer.podSecurityContext | object | `{}` | Pod security context for the initializer Job |
| initializer.resources.limits.cpu | string | `"2000m"` |  |
| initializer.resources.limits.memory | string | `"512Mi"` |  |
| initializer.resources.requests.cpu | string | `"100m"` |  |
| initializer.resources.requests.memory | string | `"256Mi"` |  |
| initializer.run | bool | `true` |  |
| initializer.staticName | bool | `false` | staticName defines whether name of the job will be the same (e.g., "defectdojo-initializer") or different every time - generated based on current time (e.g., "defectdojo-initializer-2024-11-11-18-57") This might be handy for ArgoCD deployments |
| initializer.tolerations | list | `[]` |  |
| localsettingspy | string | `""` | To add code snippet which would extend setting functionality, you might add it here It will be stored as ConfigMap and mounted `dojo/settings/local_settings.py`. For more see: https://documentation.defectdojo.com/getting_started/configuration/ For example: ``` localsettingspy: |   INSTALLED_APPS += (     'debug_toolbar',   )   MIDDLEWARE = [       'debug_toolbar.middleware.DebugToolbarMiddleware',   ] + MIDDLEWARE ``` |
| monitoring.enabled | bool | `false` |  |
| monitoring.prometheus.containerSecurityContext | object | `{}` | Optional: container security context for nginx prometheus exporter |
| monitoring.prometheus.enabled | bool | `false` | Add the nginx prometheus exporter sidecar |
| monitoring.prometheus.extraEnv | list | `[]` | Optional: additional environment variables injected to the nginx prometheus exporter container |
| monitoring.prometheus.extraVolumeMounts | list | `[]` | Array of additional volume mount points for the nginx prometheus exporter |
| monitoring.prometheus.image.digest | string | `""` |  |
| monitoring.prometheus.image.registry | string | `""` |  |
| monitoring.prometheus.image.repository | string | `"nginx/nginx-prometheus-exporter"` |  |
| monitoring.prometheus.image.tag | string | `"1.5.1"` |  |
| monitoring.prometheus.imagePullPolicy | string | `"IfNotPresent"` |  |
| monitoring.prometheus.resources | object | `{}` | Optional: add resource requests/limits for the nginx prometheus exporter container |
| networkPolicy | object | `{"annotations":{},"egress":[],"enabled":false,"ingress":[],"ingressExtend":[]}` | Enables application network policy For more info follow https://kubernetes.io/docs/concepts/services-networking/network-policies/ |
| networkPolicy.egress | list | `[]` |  ``` egress: - to:   - ipBlock:       cidr: 10.0.0.0/24   ports:   - protocol: TCP     port: 443 ``` |
| networkPolicy.ingress | list | `[]` | For more detailed configuration with ports and peers. It will ignore ingressExtend ``` ingress:  - from:     - podSelector:         matchLabels:           app.kubernetes.io/instance: defectdojo     - podSelector:         matchLabels:           app.kubernetes.io/instance: defectdojo-prometheus    ports:    - protocol: TCP      port: 8443 ``` |
| networkPolicy.ingressExtend | list | `[]` | if additional labels need to be allowed (e.g. prometheus scraper) ``` ingressExtend:  - podSelector:      matchLabels:      app.kubernetes.io/instance: defectdojo-prometheus ``` |
| podLabels | object | `{}` | Additional labels to add to the pods: ``` podLabels:   key: value ``` |
| postgresServer | string | `nil` | To use an external PostgreSQL instance (like CloudSQL), set `postgresql.enabled` to false, set items in `postgresql.auth` part for authentication, and set the address here: |
| postgresql | object | `{"architecture":"standalone","auth":{"database":"defectdojo","existingSecret":"defectdojo-postgresql-specific","password":"","secretKeys":{"adminPasswordKey":"postgresql-postgres-password","replicationPasswordKey":"postgresql-replication-password","userPasswordKey":"postgresql-password"},"username":"defectdojo"},"enabled":true,"primary":{"affinity":{},"containerSecurityContext":{"enabled":true,"runAsUser":1001},"name":"primary","nodeSelector":{},"persistence":{"enabled":true},"podSecurityContext":{"enabled":true,"fsGroup":1001},"service":{"ports":{"postgresql":5432}}},"shmVolume":{"chmod":{"enabled":false}},"volumePermissions":{"containerSecurityContext":{"runAsUser":1001},"enabled":false}}` | For more advance options check the bitnami chart documentation: https://github.com/bitnami/charts/tree/main/bitnami/postgresql |
| postgresql.enabled | bool | `true` | To use an external instance, switch enabled to `false` and set the address in `postgresServer` below |
| postgresql.primary.containerSecurityContext.enabled | bool | `true` | Default is true for K8s. Enabled needs to false for OpenShift restricted SCC and true for anyuid SCC |
| postgresql.primary.containerSecurityContext.runAsUser | int | `1001` | runAsUser specification below is not applied if enabled=false. enabled=false is the required setting for OpenShift "restricted SCC" to work successfully. |
| postgresql.primary.podSecurityContext.enabled | bool | `true` | Default is true for K8s. Enabled needs to false for OpenShift restricted SCC and true for anyuid SCC |
| postgresql.primary.podSecurityContext.fsGroup | int | `1001` | fsGroup specification below is not applied if enabled=false. enabled=false is the required setting for OpenShift "restricted SCC" to work successfully. |
| postgresql.volumePermissions.containerSecurityContext | object | `{"runAsUser":1001}` | if using restricted SCC set runAsUser: "auto" and if running under anyuid SCC - runAsUser needs to match the line above |
| redisParams | string | `""` | Parameters attached to the redis connection string, defaults to "ssl_cert_reqs=optional" if `redisScheme` is `rediss` |
| redisPort | int | `6379` | Define the protocol to use with the external Redis instance |
| redisScheme | string | `"redis"` | Define the protocol to use with the external Redis instance |
| redisServer | string | `nil` | To use an external Redis instance, set `redis.enabled` to false and set the address here: |
| revisionHistoryLimit | int | `10` | Allow overriding of revisionHistoryLimit across all deployments. |
| secrets.annotations | object | `{}` | Add annotations for secret resources |
| securityContext | object | `{"containerSecurityContext":{"runAsNonRoot":true},"enabled":true,"podSecurityContext":{"runAsNonRoot":true}}` | Security context settings |
| serviceAccount.annotations | object | `{}` | Optional additional annotations to add to the DefectDojo's Service Account. |
| serviceAccount.create | bool | `true` | Specifies whether a service account should be created. |
| serviceAccount.labels | object | `{}` | Optional additional labels to add to the DefectDojo's Service Account. |
| serviceAccount.name | string | `""` | The name of the service account to use. If not set and create is true, a name is generated using the fullname template |
| siteUrl | string | `""` | The full URL to your defectdojo instance, depends on the domain where DD is deployed, it also affects links in Jira. Use syntax: `siteUrl: 'https://<yourdomain>'` |
| tests.unitTests.automountServiceAccountToken | bool | `false` |  |
| tests.unitTests.image | object | `{"digest":"","registry":"","repository":"","tag":""}` | If empty, uses values from images.django.image |
| tests.unitTests.resources.limits.cpu | string | `"500m"` |  |
| tests.unitTests.resources.limits.memory | string | `"512Mi"` |  |
| tests.unitTests.resources.requests.cpu | string | `"100m"` |  |
| tests.unitTests.resources.requests.memory | string | `"128Mi"` |  |
| trackConfig | string | `"disabled"` | Track configuration (trackConfig): will automatically respin application pods in case of config changes detection can be: 1. disabled (default) 2. enabled, enables tracking configuration changes based on SHA256 |
| valkey | object | `{"auth":{"existingSecret":"defectdojo-valkey-specific","existingSecretPasswordKey":"valkey-password","password":""},"enabled":true,"sentinel":{"enabled":false},"service":{"port":6379},"tls":{"enabled":false}}` | For more advance options check the bitnami chart documentation: https://artifacthub.io/packages/helm/cloudpirates-valkey/valkey |
| valkey.enabled | bool | `true` | To use an external instance, switch enabled to `false` and set the address in `redisServer` below |
| valkey.service | object | `{"port":6379}` | To use a different port for Redis (default: 6379) |
| valkey.tls.enabled | bool | `false` | If TLS is enabled, the Redis broker will use the redis:// and optionally mount the certificates from an existing secret. |
| valkeyParams | string | `""` | Parameters attached to the valkey connection string, defaults to "ssl_cert_reqs=optional" if `valkey.tls.enabled` |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)
