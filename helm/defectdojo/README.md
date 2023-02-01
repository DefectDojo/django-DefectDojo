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

## Parameters

### Global settings

| Name                             | Description                                                                                                | Value                               |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| `createSecret`                   | create defectdojo specific secret                                                                          | `false`                             |
| `createRabbitMqSecret`           | create rabbitmq secret in defectdojo chart, outside of rabbitmq chart                                      | `false`                             |
| `createRedisSecret`              | create redis secret in defectdojo chart, outside of redis chart                                            | `false`                             |
| `createMysqlSecret`              | create mysql secret in defectdojo chart, outside of mysql chart                                            | `false`                             |
| `createPostgresqlSecret`         | create postgresql secret in defectdojo chart, outside of postgresql chart                                  | `false`                             |
| `createPostgresqlHaSecret`       | create postgresql-ha secret in defectdojo chart, outside of postgresql-ha chart                            | `false`                             |
| `createPostgresqlHaPgpoolSecret` | create postgresql-ha-pgpool secret in defectdojo chart, outside of postgresql-ha chart                     | `false`                             |
| `trackConfig`                    | will automatically respin application pods in case of config changes detection, disabled (default)/enabled | `disabled`                          |
| `database`                       | Option to use "postgresql" or "mysql" database type, by default "mysql" is chosen                          | `postgresql`                        |
| `host`                           | Primary hostname of instance                                                                               | `defectdojo.default.minikube.local` |


### Image

| Name               | Description                                                                                            | Value        |
| ------------------ | ------------------------------------------------------------------------------------------------------ | ------------ |
| `imagePullPolicy`  | Kubernetes image pull policy, https://kubernetes.io/docs/concepts/containers/images/#image-pull-policy | `Always`     |
| `repositoryPrefix` | Where to pull the defectDojo images from. Defaults to "defectdojo/*" repositories on hub.docker.com    | `defectdojo` |
| `imagePullSecrets` | Image pull secret                                                                                      | `[]`         |
| `tag`              | Image tag                                                                                              | `latest`     |
| `podLabels`        | Additional labels to add to the pods                                                                   | `{}`         |
| `securityContext`  | Pod Security Context                                                                                   | `undefined`  |


### Admin setup

| Name                            | Description                        | Value                    |
| ------------------------------- | ---------------------------------- | ------------------------ |
| `admin.user`                    | Admin username                     | `admin`                  |
| `admin.password`                | Admin password (default generated) | `""`                     |
| `admin.firstName`               | Admin first name                   | `Administrator`          |
| `admin.lastName`                | Admin last name                    | `User`                   |
| `admin.mail`                    | Admin email                        | `admin@defectdojo.local` |
| `admin.secretKey`               | Secret key                         | `""`                     |
| `admin.credentialAes256Key`     | credentialAes256Key                | `""`                     |
| `admin.metricsHttpAuthPassword` | metricsHttpAuthPassword            | `""`                     |


### Monitoring

| Name                                    | Description         | Value                                    |
| --------------------------------------- | ------------------- | ---------------------------------------- |
| `monitoring.enabled`                    | Enabled monitoring  | `false`                                  |
| `monitoring.prometheus.enabled`         | Adds sidecar        | `false`                                  |
| `monitoring.prometheus.image`           | Sidecar image       | `nginx/nginx-prometheus-exporter:0.11.0` |
| `monitoring.prometheus.imagePullPolicy` | Sidecar pull policy | `IfNotPresent`                           |


### Database




### Message Broker




### Extra configs

| Name           | Description                                                                                                                                                                                            | Value |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----- |
| `extraConfigs` | Add extra variables not predefined by helm config it is possible to define in extraConfigs block                                                                                                       | `{}`  |
| `extraSecrets` | Extra secrets can be created inside of extraSecrets block. NOTE do not store sensitive data in plain text form, better inject it during the deployment/upgrade by --set extraSecrets.secret=someSecret | `{}`  |
| `extraEnv`     | Add (or override) extra variables which need to be pulled from another configMap                                                                                                                       | `[]`  |


## Upgrading
