
# Installing DefectDojo using helm

## Install helm chart

```bash
helm repo add defectdojo 'https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/helm-charts'
helm repo update
```

You can then run `helm search repo defectdojo` to see the charts.

## Getting started

Once you have installed the chart, you will need to setup a few things to get started.

As show in the chart, on the first lines, you have to chosse if the helm chart should build secret or not. In the case that you want to manage your own secret, you can just let the following fields with default values:

```yml
# Global settings
# create defectdojo specific secret
createSecret: false
```

**Important:** If you choose to create the secret on your own, you will need to create a secret named `defectdojo` and containing the following fields:

- DD_ADMIN_PASSWORD
- DD_SECRET_KEY
- DD_CREDENTIAL_AES_256_KEY
- METRICS_HTTP_AUTH_PASSWORD

Theses fields are required to get the stack running.

## HOW TO

### Setup an external postgres database

If you want to use your own database instance, you will need to change a bit of configuration.
Here is a simple example of all the fields that you need to configure.

```yml
database: postgresql # refer to the following configuration

postgresql:
  enabled: false # Disable the creation of the database in the cluster
  postgresServer: "127.0.0.1" # Required to skip certains tests not useful on external instances
  auth:
    username: defectdojo # you database user
    database: defectdojo # you database name
    secretKeys: 
      adminPasswordKey: password # the name of the field containing the password value
      userPasswordKey: password # the name of the field containing the password value
      replicationPasswordKey: password # the name of the field containing the password value
    existingSecret: postgresql-password # the secret containing your database password

extraEnv:
# Overwrite the database endpoint
- name: DD_DATABASE_HOST
  valueFrom:
    configMapKeyRef:
      name: postgresql-config
      key: host
# Overwrite the database port
- name: DD_DATABASE_PORT
  valueFrom:
    configMapKeyRef:
      name: postgresql-config
      key: port
```
