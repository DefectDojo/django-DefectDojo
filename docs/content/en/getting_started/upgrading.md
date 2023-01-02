---
title: "Upgrading"
description: "Release specific upgrading instructions"
draft: false
weight: 5
---

Docker-compose
--------------

When you deploy a vanilla docker-compose, it will create a persistent
volume for your MySQL database. As long as your volume is there, you
should not lose any data.

### Using docker images provided in DockerHub

{{% alert title="Information" color="info" %}}
If you\'re using `latest`, then you need to pre pull the `latest` from
DockerHub to update.
{{% /alert %}}


The generic upgrade method for docker-compose follows these steps:

-   Pull the latest version

    ``` {.sourceCode .bash}
    docker pull defectdojo/defectdojo-django:latest
    docker pull defectdojo/defectdojo-nginx:latest
    ```

-   If you would like to use something older (so not the latest
    version), specify the version (tag) you want to upgrade to:

    ``` {.sourceCode .bash}
    docker pull defectdojo/defectdojo-django:1.10.2
    docker pull defectdojo/defectdojo-nginx:1.10.2
    ```

-   Go to the directory where your docker-compose.yml file lives
-   Stop DefectDojo: `./dc-stop.sh`
-   Re-start DefectDojo, allowing for container recreation:
    `./dc-up-d.sh`
-   Database migrations will be run automatically by the initializer.
    Check the output via `docker-compose logs initializer` or relevant k8s command
-   If you have the initializer disabled (or if you want to be on the
    safe side), run the migration command:
    `docker-compose exec uwsgi /bin/bash -c 'python manage.py migrate`

### Building your local images

If you build your images locally and do not use the ones from DockerHub,
the instructions are much the same, except that you'd build your images
first. (Of course, if you're doing this, then you know you have to
update the source code first)

Replace the first step above with this one: `docker-compose build`

godojo installations
--------------------

If you have installed DefectDojo on "iron" and wish to upgrade the installation, please see the [instructions in the repo](https://github.com/DefectDojo/godojo/blob/master/docs-and-scripts/upgrading.md).

## Upgrading to DefectDojo Version 2.18.x

**Upgrade instructions for helm chart with rabbitMQ enabled**: The rabbitMQ uses a statefulset by default. Before upgrading the helm chart we have to ensure that all queues are empty:

```bash
kubectl exec -i <name_of_the_rabbitmq_pod>  -- rabbitmqctl list_queues
```

Next step is to delete rabbitMQ pvc:

```bash
kubectl delete  pvc -l app.kubernetes.io/name=rabbitmq
```

Last step is to perform the upgrade.

For more information: https://artifacthub.io/packages/helm/bitnami/rabbitmq/11.2.0



## Upgrading to DefectDojo Version 2.17.x.

There are no special instruction for upgrading to 2.17.0. Check the [Release Notes](https://github.com/DefectDojo/django-DefectDojo/releases/tag/2.17.0) for the contents of the release.

## Upgrading to DefectDojo Version 2.16.x.

There are no special instruction for upgrading to 2.16.0. Check the [Release Notes](https://github.com/DefectDojo/django-DefectDojo/releases/tag/2.16.0) for the contents of the release.

## Upgrading to DefectDojo Version 2.15.x.

There are no special instruction for upgrading to 2.15.0. Check the [Release Notes](https://github.com/DefectDojo/django-DefectDojo/releases/tag/2.15.0) for the contents of the release.

## Upgrading to DefectDojo Version 2.13.x.

The last release implemented the search for vulnerability ids, but the search database was not initialized. To populate the database table of the vulnerability ids, execute this django command from the defect dojo installation directory or from a shell of the Docker container or Kubernetes pod:

`./manage.py migrate_cve`

Additionally this requires a one-time rebuild of the Django-Watson search index. Execute this django command from the defect dojo installation directory or from a shell of the Docker container or Kubernetes pod:

`./manage.py buildwatson`

**Upgrade instructions for helm chart with postgres enabled**: The postgres database uses a statefulset by default. Before upgrading the helm chart we have to delete the statefullset and ensure that the pvc is reused, to keep the data. For more information: https://docs.bitnami.com/kubernetes/infrastructure/postgresql/administration/upgrade/ .

```bash
helm repo update
helm dependency update ./helm/defectdojo

# obtain name oft the postgres pvc
export POSTGRESQL_PVC=$(kubectl get pvc -l app.kubernetes.io/instance=defectdojo,role=primary -o jsonpath="{.items[0].metadata.name}")

# delete postgres statefulset
kubectl delete statefulsets.apps defectdojo-postgresql --namespace default --cascade=orphan

# upgrade
helm upgrade \
  defectdojo \
  ./helm/defectdojo/ \
  --set primary.persistence.existingClaim=$POSTGRESQL_PVC \
  ... # add your custom settings
```

**Further changes:**

Legacy authorization for changing configurations based on staff users has been removed.

## Upgrading to DefectDojo Version 2.12.x.

**Breaking change for search:** The field `cve` has been removed from the search index for Findings and the Vulnerability Ids have been added to the search index. With this the syntax to search explicitly for vulnerability ids have been changed from `cve:` to `vulnerability_id:`, e.g. `vulnerability_id:CVE-2020-27619`.


## Upgrading to DefectDojo Version 2.10.x.

**Breaking change for Findings:** The field `cve` will be replaced by a list of Vulnerability Ids, which can store references to security advisories associated with this finding. These can be Common Vulnerabilities and Exposures (CVE) or from other sources, eg. GitHub Security Advisories. Although the field does still exist in the code, the API and the UI have already been changed to use the list of Vulnerability Ids. Other areas like hash code calculation, search and parsers will be migrated step by step in later stages.

This change also causes an API change for the endpoint `/engagements/{id}/accept_risks/`.


## Upgrading to DefectDojo Version 2.9.x.

**Breaking change for APIv2:** `configuration_url` was removed from API endpoint `/api/v2/tool_configurations/` due to redundancy.


## Upgrading to DefectDojo Version 2.8.x.

**Breaking change for Docker Compose:** Starting DefectDojo with Docker Compose now supports 2 databases (MySQL and PostgreSQL) and 2 celery brokers (RabbitMQ and Redis). To make this possible, docker-compose needs to be started with the parameters `--profile` and `--env-file`. You can get more information in [Setup via Docker Compose - Profiles](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md#setup-via-docker-compose---profiles). The profile `mysql-rabbitmq` provides the same configuration as in previous releases. With this the prerequisites have changed as well: Docker requires at least version 19.03.0 and Docker Compose 1.28.0.

**Breaking change for Helm Chart:** In one of the last releases we upgraded the redis dependency in our helm chart without renaming keys in our helm chart. We fixed this bug with this release, but you may want to check if all redis values are correct ([Pull Request](https://github.com/DefectDojo/django-DefectDojo/pull/5886)).

The flexible permissions for the configuration of DefectDojo are now active by default. With this, the flag **Staff** for users is not relevant and not visible anymore. The old behaviour can still be activated by setting the parameter `FEATURE_CONFIGURATION_AUTHORIZATION` to `False`. If you haven't done so with the previous release, you can still run a migration script with `./manage.py migrate_staff_users`. This script:

* creates a group for all staff users,
* sets all configuration permissions that staff users had and
* sets the global Owner role, if `AUTHORIZATION_STAFF_OVERRIDE` is set to `True`.

## Upgrading to DefectDojo Version 2.7.x.

This release is a breaking change regarding the Choctaw Hog parser. As the maintainers of this project unified multiple parsers under the RustyHog parser, we now support the parsing of Choctaw Hog JSON output files through the Rusty Hog parser. Furthermore, we also support Gottingen Hog and Essex Hog JSON output files with the RustyHog parser.

There is another breaking change regarding the import of SSLyze scans. The parser has been renamed from `SSLyze 3 Scan (JSON)` to `SSLyze Scan (JSON)`. The data in the database is fixed by the initializer, but it may break scripted API calls.

Release 2.7.0 contains a beta functionality to make permissions for the configuration of DefectDojo more flexible. When the settings parameter `FEATURE_CONFIGURATION_AUTHORIZATION` is set to `True`, many configuration dialogues and API endpoints can be enabled for users or groups of users, regardless of their **Superuser** or **Staff** status, see [Configuration Permissions]({{< ref "../usage/permissions/#configuration-permissions" >}}).

The functionality using the flag `AUTHORIZATION_STAFF_OVERRIDE` has been removed. The same result can be achieved with giving the staff users a global Owner role. 

To support the transition for these 2 changes, you can run a migration script with ``./manage.py migrate_staff_users``. This script:

* creates a group for all staff users,
* sets all configuration permissions that staff users had and
* sets the global Owner role, if `AUTHORIZATION_STAFF_OVERRIDE` is set to `True`.

## Upgrading to DefectDojo Version 2.6.x.

There are no special instruction for upgrading to 2.6.0. Check the [Release Notes](https://github.com/DefectDojo/django-DefectDojo/releases/tag/2.6.0) for the contents of the release.

Please consult the security advisories [GHSA-f82x-m585-gj24](https://github.com/DefectDojo/django-DefectDojo/security/advisories/GHSA-f82x-m585-gj24) (moderate) and [GHSA-v7fv-g69g-x7p2](https://github.com/DefectDojo/django-DefectDojo/security/advisories/GHSA-v7fv-g69g-x7p2) (high) to see what security issues were fixed in this release. These will be published and become visible at January 18th, 2022.

## Upgrading to DefectDojo Version 2.5.x.

Legacy authorization has been completely removed with version 2.5.0. This includes removal of the migration of users
to the new authorization as described in https://documentation.defectdojo.com/getting_started/upgrading/#authorization.
If you are still using the legacy authorization, you should run the migration with ``./manage.py migrate_authorization_v2``
before upgrading to version 2.5.0

This release introduces the "Forgot password" functionality (`DD_FORGOT_PASSWORD`: default `True`). The function
allows sending an e-mail with the reset password link. Missing configuration or misconfiguration of SMTP
(`DD_EMAIL_URL`) could raise an error (HTTP-500). Check and test (for example by resetting your own password) if you
configured SMTP correctly. If you want to avoid HTTP-500 and you don't want to set up SMTP, you can just simply switch
off the "Forgot password" functionality (`DD_FORGOT_PASSWORD=False`).

Release renamed system setting `mail_notifications_from` to `email_from`. This value will not be used only for sending
notifications but also for sending the reset password emails. It is highly recommended to check the content of this
value if you are satisfied. If you installed DefectDojo earlier, you can expect `"from@example.com"` there. A fresh
installation will use `"no-reply@example.com"`

This release [updates](https://github.com/DefectDojo/django-DefectDojo/pull/5450) our helm dependencies. There is a breaking change if you are using the mysql database from the helm chart because we replaced the deprecated chart from the stable repo with a chart from bitnami. If you have persistance enabled, ensure to backup your data before upgrading. All data get lost when replacing the mysql chart during the upgrade. For data migration take a look at the mysql backup and restore process.

Furthermore we updated our kubernetes version. Current tests run on 1.18.16 and 1.22.0.

## Upgrading to DefectDojo Version 2.4.x. (Security Release)

This releases fixes a High severity vulnerability for which the details will be disclosed on November 16th in [GHSA-fwg9-752c-qh8w](https://github.com/DefectDojo/django-DefectDojo/security/advisories/GHSA-fwg9-752c-qh8w)

There is a breaking change in the API for importing and re-importings scans with SonarQube API and Cobalt.io API. The [scan configurations
have been unified](https://github.com/DefectDojo/django-DefectDojo/pull/5289) and are set now with the attribute `api_scan_configuration`.
The existing configurations for SonarQube API and Cobalt.io API have been migrated.

At the request of pyup.io, we had to remove the parser for Safety scans.


## Upgrading to DefectDojo Version 2.3.x.

There are no special instruction for upgrading to 2.3.0.
In 2.3.0 we [changed the default password hashing algorithm to Argon2 (from PBKDF2)](https://github.com/DefectDojo/django-DefectDojo/pull/5205).
When logging in, exising hashes get replaced by an Argon2 hash. If you want to rehash password without users having to login,
please see the [Django password management docs](https://docs.djangoproject.com/en/3.2/topics/auth/passwords/).
The previous password hashing algorithm (PBKDF2) was not unsafe, but we wanted to follow the [OWASP guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).


## Upgrading to DefectDojo Version 2.2.x.

Upgrade to 2.0.0 contained migration of endpoints. Some parts of migration haven't been done properly. This deficiency
may manifest as a doubled slash in endpoint URLs (like `http://foo.bar:8080//test`) or as a problem with deduplication
of the same endpoints. The mentioned bug was fixed in 2.2.0 and if you have seen these kinds of problems, just rerun
"Endpoint migration" as it is written in [Upgrading to DefectDojo Version 2.0.x.](#upgrading-to-defectdojo-version-20x).


## Upgrading to DefectDojo Version 2.0.x.

Follow the usual steps to upgrade as described above.

BEFORE UPGRADING
- If you are using SAML2 checkout the new [documentaion](https://documentation.defectdojo.com/integrations/social-authentication/#saml-20) and update you settings following the migration section. We replaced [django-saml2-auth](https://github.com/fangli/django-saml2-auth) with [djangosaml2](https://github.com/IdentityPython/djangosaml2).

AFTER UPGRADING
- Usual migration process (`python manage.py migrate`) try to migrate all endpoints to new format and merge duplicates.
- All broken endpoints (which weren't possible to migrate) have red flag 🚩 in standard list of endpoints.
- Check if all your endpoints was migrated successfully, go to: https://<defect-dojo-url>/endpoint/migrate.
- Alternatively, this can be run as management command:  `docker-compose exec uwsgi ./manage.py endpoint_migration --dry-run`
- When all endpoint will be fixed (there is not broken endpoint), press "Run migration" in https://<defect-dojo-url>/endpoint/migrate
- Or, you can run management command: `docker-compose exec uwsgi ./manage.py endpoint_migration`
- Details about endpoint migration / improvements in https://github.com/DefectDojo/django-DefectDojo/pull/4473

We decided to name this version 2.0.0 because we did some big cleanups in this release:

- Remove API v1 ([#4413](https://github.com/DefectDojo/django-DefectDojo/pull/4413))
- Remove setup.bash installation method ([#4417](https://github.com/DefectDojo/django-DefectDojo/pull/4417))
- Rename Finding.is_Mitigated field to Finding.is_mitigated ([#3854](https://github.com/DefectDojo/django-DefectDojo/pull/4854))
- Remove everything related to the old tagging library ([#4419](https://github.com/DefectDojo/django-DefectDojo/pull/4419))
- Remove S0/S1/S2../S5 severity display option ([#4415](https://github.com/DefectDojo/django-DefectDojo/pull/4415))
- Refactor EndPoint handling/formatting ([#4473](https://github.com/DefectDojo/django-DefectDojo/pull/4473))
- Upgrade to Django 3.x ([#3632](https://github.com/DefectDojo/django-DefectDojo/pull/3632))
- PDF Reports removed ([#4418](https://github.com/DefectDojo/django-DefectDojo/pull/4418))
- Hashcode calculation logic has changed. To update existing findings run:

  `./manage.py dedupe --hash_code_only`.

If you're using docker:

`docker-compose exec uwsgi ./manage.py dedupe --hash_code_only`.

This can take a while depending on your instance size.

- See release notes: https://github.com/DefectDojo/django-DefectDojo/releases/tag/2.0.0

### Endpoints

- The usual migration process (`python manage.py migrate`) tries to migrate all endpoints to new format and merge duplicates.
- All broken endpoints (which weren't possible to migrate) have a red flag 🚩 in the standard list of endpoints.
- Check if all your endpoints were migrated successfully, go to: https://<defect-dojo-url>/endpoint/migrate.
- Alternatively, this can be run as management command:  `docker-compose exec uwsgi ./manage.py endpoint_migration --dry-run`
- When all endpoint are fixed (there is not broken endpoint), press "Run migration" in https://<defect-dojo-url>/endpoint/migrate
- Or, you can run management command: `docker-compose exec uwsgi ./manage.py endpoint_migration`
- Details about endpoint migration / improvements in https://github.com/DefectDojo/django-DefectDojo/pull/4473

### Authorization

The new authorization system for Products and Product Types based on roles is the default now. The fields for authorized users are not available anymore, but you can assign roles as described in [Permissions](../../usage/permissions). Users are migrated automatically, so that their permissions are as close as possible to the previous authorization:
- Superusers will still have all permissions on Products and Product Types, so they must not be changed.
- Staff users have had all permissions for all product types and products, so they will be get a global role as *Owner*.
- Product_Members and Product Type_Members will be added for authorized users according to the settings for the previous authorization:
  - The *Reader* role is set as the default.
  - If `AUTHORIZED_USERS_ALLOW_STAFF` is `True`, the user will get the *Owner* role for the respective Product or Product Type.
  - If `AUTHORIZED_USERS_ALLOW_CHANGE` or `AUTHORIZED_USERS_ALLOW_DELETE` is `True`, the user will get the *Writer* role for the respective Product or Product Type.

The new authorization is active for both UI and API. Permissions set via authorized users or via the Django Admin interface are no longer taken into account.

Please review the roles for your users after the upgrade to avoid an unintended permissions creep.


## Upgrading to DefectDojo Version 1.15.x

- See release notes: https://github.com/DefectDojo/django-DefectDojo/releases/tag/1.15.0
- If you have made changes to JIRA templates or the template config in the JIRA Project config for instances/products/engagements:
The jira template settings introduced in 1.13 have been changed. You now have to select a subfolder instead of a sinlge template file. If you have chosen a non-default template here, you have to reapply that to all products / engagements. Also you have to move your custom templates into the correct subfolder in `dojo/templates/issue-trackers/`.
- Hashcode calculation logic has changed in #4134, #4308 and #4310 to update existing findings run:

    `./manage.py dedupe --hash_code_only`

If you're using docker:

`docker-compose exec uwsgi ./manage.py dedupe --hash_code_only`

This can take a while depending on your instance size.



## Upgrading to DefectDojo Version 1.14.x

- See release notes: https://github.com/DefectDojo/django-DefectDojo/releases/tag/1.14.0

Note that the below fields are now optional without default value. They will not be filled anymore with values such as "No references given" when found empty while saving the findings
- mitigation
- references
- impact
- url



## Upgrading to DefectDojo Version 1.13.x

- See release notes: https://github.com/DefectDojo/django-DefectDojo/releases/tag/1.13.0
- Hashcode settings affecting deduplication have changed, to update existing findings run:

    `./manage.py dedupe`

If you're using docker:

    docker-compose exec uwsgi ./manage.py dedupe

This can take a while depeneding on your instance size. It might possible that new duplicates are detected among existing findings, so make a backup before running!


## Upgrading to DefectDojo Version 1.12.x

- See release notes: https://github.com/DefectDojo/django-DefectDojo/releases/tag/1.12.0
- 1.12.1 is a security release https://github.com/DefectDojo/django-DefectDojo/releases/tag/1.12.1

## Upgrading to DefectDojo Version 1.11.x

- See release notes: https://github.com/DefectDojo/django-DefectDojo/releases/tag/1.11.0
- 1.11.1 is a security release https://github.com/DefectDojo/django-DefectDojo/releases/tag/1.11.1

## Upgrading to DefectDojo Version 1.10.x

**1.10.4 is a security release**

-   See the security advisory:
    <https://github.com/DefectDojo/django-DefectDojo/security/advisories/GHSA-96vq-gqr9-vf2c>
-   See release notes:
    <https://github.com/DefectDojo/django-DefectDojo/releases/tag/1.10.4>
-   Version 1.10.4 replaces 1.10.3 as the latter contained an incomplete
    fix

**What\'s New:**

-   See release notes:
    <https://github.com/DefectDojo/django-DefectDojo/releases>
-   DefectDojo now provides a `settings.py` file
    out-of-the-box. Custom settings need to go into
    `local\_settings.py`. See
    <https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/settings.py>
    and
    <https://github.com/DefectDojo/django-DefectDojo/blob/master/docker/extra_settings/README.md>
-   A quickfix is to rename your own / customized
    `settings.py` or `settings.dist.py` to
    `local\_settings.py`. Details of that PR:
    <https://github.com/DefectDojo/django-DefectDojo/pull/3136>
-   Major JIRA integration refactoring, for which you should at least
    use 1.10.1 and not 1.10.0 for many bug fixes.

**Breaking changes**

Kubernetes/Helm users: we have moved away from the \"stable\" repository
to \"bitnami\" in this release. The bitnami postgresql chart required us
to add a new key to the postgresql secret, which will give you the error
`postgresql-postgres-password is missing` if you have
`createPostgresqlSecret: false`. In 1.10.1, a fix was also included to
allow your existing `postgresqlPassword` to be reused properly.

Including in 1.10.1 were a couple fixes related to a rabbitMQ upgrade.
The path to access `password`, `erlangCookie` and
`existingPasswordSecret` changed from `rabbitmq` to `auth`. Furthermore,
as rabbitMQ is deployed as a StatefulSet, an in-place upgrade is not
possible and an error will likely be thrown such as
`Forbidden: updates to statefulset spec for fields other than 'replicas', 'template', and 'updateStrategy' are forbidden`.
After ensuring your rabbitMQ celery queue is empty, you will then want
to delete your rabbitMQ StatefulSet and PVC to allow them to get
re-created, or fully delete and recreate defectdojo.

## Upgrading to DefectDojo Version 1.9.3

**This is a security release**

-   See the [security
    advisory](https://github.com/DefectDojo/django-DefectDojo/security/advisories/GHSA-8q8j-7wc4-vjg5)
-   See [release
    notes](https://github.com/DefectDojo/django-DefectDojo/releases/tag/1.9.3)

**What\'s New:**

-   See release notes:
    <https://github.com/DefectDojo/django-DefectDojo/releases>

**NOTE:**

When upgrading from before 1.9.2, a corrective script may need to be ran

`./manage.py create\_endpoint\_status`

If you\'re using docker:

`docker-compose exec uwsgi ./manage.py create\_endpoint\_status`

This can take a while depending on your hardware and the number of
findings in your instance.

-   Search index tweaking index rebuild after upgrade:

This requires a (one-time) rebuild of the Django-Watson search index.
Execute the django command from the defect dojo installation directory:

`./manage.py buildwatson]`

If you\'re using docker:

`docker-compose exec uwsgi ./manage.py buildwatson`

This can take a while depending on your hardware and the number of
findings in your instance.

## Upgrading to DefectDojo Version 1.8.0

**What\'s New:**

-   See release notes:
    <https://github.com/DefectDojo/django-DefectDojo/releases>
-   Improved search, which requires an index rebuild
    (<https://github.com/DefectDojo/django-DefectDojo/pull/2861>)

This requires a (one-time) rebuild of the Django-Watson search index.
Execute the django command from the defect dojo installation directory:

`./manage.py buildwatson`

If you\'re using docker:

`docker-compose exec uwsgi ./manage.py buildwatson`

This can take a while depending on your hardware and the number of
findings in your instance.

-   **NOTE:**

As a result of a breaking bug revolving around Endpoint\_status objects,
a corrective script will need to be ran after every dynamic scan
imported through either API version.

The script can be found
[here](https://github.com/DefectDojo/django-DefectDojo/blob/dev/dojo/management/commands/create_endpoint_status.py)

`./manage.py create\_endpoint\_status`

If you\'re using docker:

`docker-compose exec uwsgi ./manage.py create\_endpoint\_status`

This can take a while depending on your hardware and the number of
findings in your instance.

## Upgrading to DefectDojo Version 1.7.0

**What\'s New:**

-   Updated search, you can now search for CVE-XXXX-YYYY
-   Updated search index, fields added to index: \'id\', \'title\',
    \'cve\', \'url\', \'severity\', \'description\', \'mitigation\',
    \'impact\', \'steps\_to\_reproduce\', \'severity\_justification\',
    \'references\', \'sourcefilepath\', \'sourcefile\', \'hash\_code\',
    \'file\_path\', \'component\_name\', \'component\_version\',
    \'unique\_id\_from\_tool\'

This requires a (one-time) rebuild of the Django-Watson search index.
Execute the django command from the defect dojo installation directory:

`./manage.py buildwatson dojo.Finding`

If you\'re using docker:

`docker-compose exec uwsgi ./manage.py buildwatson dojo.Finding`

Upgrading to DefectDojo Version 1.5.0
-------------------------------------

**What\'s New:**

-   Updated UI with a new DefectDojo logo, default colors and CSS.
-   Updated Product views with tabs for Product Overview, Metrics,
    Engagements, Endpoints, Benchmarks (ASVS), and Settings to make it
    easier to navigate and manage your products.
-   New Product Information fields: Regulations, Criticality, Platform,
    Lifecycle, Origin, User Records, Revenue, External Audience,
    Internet Accessible
-   Languages pie chart on product overview, only supported through the
    API and Django admin, integrates with cloc analyzer
-   New Engagement type of CI/CD to support continual testing
-   Engagement shortcuts and ability to import findings and auto-create
    an engagement
-   Engagement labels for overdue, no tests and findings
-   New Contextual menus throughout DefectDojo and shortcuts to new
    findings and critical findings
-   Ability to merge a finding into a parent finding and either
    inactivate or delete the merged findings.
-   Report improvements and styling adjustment with the default option
    of HTML reports
-   SLA for remediation of severities based on finding criticality, for
    example critical findings remediated within 7 days. Configurable in
    System Settings.
-   Engagement Auto-Close Days in System Settings. Automatically close
    an engagement if open past the end date.
-   Ability to apply remediation advice based on CWE. For example XSS
    can be configured as a template so that it\'s consistent across all
    findings. Enabled in system settings.
-   Finding confidence field supported from scanners. First
    implementation in the Burp importer.
-   Goast importer for static analysis of Golang products
-   Celery status check on System Settings
-   Beta rules framework release for modifying findings on the fly
-   DefectDojo 2.0 API with Swagger support
-   Created and Modified fields on all major tables
-   Various bug fixes reported on Github

**Upgrading to 1.5.0 requirements:**

1.  Back up your database first, ideally take the backup from production
    and test the upgrade on a staging server.
2.  Edit the settings.py file which can be found in
    `django-DefectDojo/dojo/settings/settings.py`. Copy in the rest
    framework configuration after the CSRF\_COOKIE\_SECURE = True:

        REST_FRAMEWORK = {
            'DEFAULT_AUTHENTICATION_CLASSES': (
                'rest_framework.authentication.TokenAuthentication',
                'rest_framework.authentication.BasicAuthentication',
            ),
            'DEFAULT_PERMISSION_CLASSES': (
                'rest_framework.permissions.DjangoModelPermissions',
            ),
            'DEFAULT_RENDERER_CLASSES': (
                'rest_framework.renderers.JSONRenderer',
            ),
            'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination',
            'PAGE_SIZE': 25
        }

Navigate to: LOGIN\_EXEMPT\_URLS and add the following after
r\'\^%sfinding/image/(?P\<token\>\[\^/\]+)\$\' % URL\_PREFIX:

    r'^%sfinding/image/(?P<token>[^/]+)$' % URL_PREFIX,
    r'^%sapi/v2/' % URL_PREFIX,

Navigate to: INSTALLED\_APPS and add the following after:
\'multiselectfield\',:

    'multiselectfield',
    'rest_framework',
    'rest_framework.authtoken',
    'rest_framework_swagger',
    'dbbackup',

Navigate to: CELERY\_TASK\_IGNORE\_RESULT = True and add the following
after CELERY\_TASK\_IGNORE\_RESULT line:

    CELERY_RESULT_BACKEND = 'db+sqlite:///dojo.celeryresults.sqlite'

Save your modified settings file. For reference the modified file should
look like the new 1.5.0
\[settings\](<https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/settings.dist.py>)
file, minus the environmental configurations. As an alternative this
file can be used and the enviromental configurations from you
environment can be copied into this file.

3.  Activate your virtual environment and then upgrade the requirements:

`pip install -r requirements.txt --upgrade`

4.  Upgrade the database:

        ./manage.py makemigrations
        ./manage.py migrate

5.  Collect the static files (Javascript, Images, CSS):

        ./manage.py collectstatic --noinput

6.  Complete

## Upgrading to DefectDojo Version 1.3.1

**What\'s New:**

-   New importers for Contrast, Nikto and TruffleHog (finding secrets in
    git repos).
-   Improved merging of findings for dynamic and static importers
-   Markdown support for findings
-   HTML report improvements including support of Markdown.
-   System settings Celery status page to assist in debugging if Celery
    is functional.

**Upgrading to 1.3.1 requires:**

1.  pip install markdown pip install pandas
2.  ./manage.py makemigrations ./manage.py migrate
3.  ./manage.py collectstatic \--noinput
4.  Complete

## Upgrading to DefectDojo Version 1.2.9

**What\'s New:** New feature: Benchmarks (OWASP ASVS)

**Upgrading to 1.2.9 requires:**

1.  ./manage.py makemigrations ./manage.py migrate ./manage.py loaddata
    dojo/fixtures/benchmark\_type.json ./manage.py loaddata
    dojo/fixtures/benchmark\_category.json ./manage.py loaddata
    dojo/fixtures/benchmark\_requirement.json
2.  ./manage.py collectstatic \--noinput
3.  Complete

## Upgrading to DefectDojo Version 1.2.8

New feature: Product Grading (Overall Product Health) Upgrading to 1.2.8
requires:

1.  ./manage.py makemigrations ./manage.py migrate ./manage.py
    system\_settings
2.  ./manage.py collectstatic \--noinput
3.  pip install asteval
4.  pip install \--upgrade celery
5.  Complete

## Upgrading to DefectDojo Version 1.2.4

Upgrading to 1.2.4 requires:

1.  ./manage.py makemigrations ./manage.py migrate ./manage.py loaddata
    dojo/fixtures/objects\_review.json

## Upgrading to DefectDojo Version 1.2.3

Upgrading to 1.2.3 requires:

1.  ./manage.py makemigrations ./manage.py migrate ./manage.py loaddata
    dojo/fixtures/language\_type.json
2.  Currently languages and technologies can be updated via the API or
    in the admin section of Django.

## July 6th 2017 - New location for system settings

Pull request \#313 moves a number of system settings previously located
in the application\'s settings.py to a model that can be used and
changed within the web application under \"Configuration -\> System
Settings\".

If you\'re using a custom `URL_PREFIX` you will need to set this in the
model after upgrading by editing `dojo/fixtures/system_settings.json`
and setting your URL prefix in the `url_prefix` value there. Then issue
the command `./manage.py loaddata system_settings.json` to load your
settings into the database.

If you\'re not using a custom `URL_PREFIX`, after upgrading simply go to
the System Settings page and review which values you want to set for
each setting, as they\'re not automatically migrated from settings.py.

If you like you can then remove the following settings from settings.py
to avoid confusion:

-   `ENABLE_DEDUPLICATION`
-   `ENABLE_JIRA`
-   `S_FINDING_SEVERITY_NAMING`
-   `URL_PREFIX`
-   `TIME_ZONE`
-   `TEAM_NAME`

## Upgrading to DefectDojo Version 1.2.2

Upgrading to 1.2.2 requires:

1.  Copying settings.py to the settings/ folder.
2.  If you have supervisor scripts change
    DJANGO\_SETTINGS\_MODULE=dojo.settings.settings

## Upgrading to Django 1.1.5

If you are upgrading an existing version of DefectDojo, you will need to
run the following commands manually:

1.  First install Yarn. Follow the instructions based on your OS:
    <https://yarnpkg.com/lang/en/docs/install/>
2.  The following must be removed/commented out from `settings.py`: :

        'djangobower.finders.BowerFinder',

        From the line that contains:
        # where should bower install components
        ...

        To the end of the bower declarations
          'justgage'
        )

3.  The following needs to be updated in `settings.py`: :

        STATICFILES_DIRS = (
            # Put strings here, like "/home/html/static" or "C:/www/django/static".
            # Always use forward slashes, even on Windows.
            # Don't forget to use absolute paths, not relative paths.
            os.path.dirname(DOJO_ROOT) + "/components/yarn_components",
        )

## Upgrading to Django 1.11

Pull request \#300 makes DefectDojo Django 1.11 ready. A fresh install
of DefectDojo can be done with the setup.bash script included - no
special steps are required.

If you are upgrading an existing installation of DefectDojo, you will
need to run the following commands manually: :

    pip install django-tastypie --upgrade
    pip install django-tastypie-swagger --upgrade
    pip install django-filter --upgrade
    pip install django-watson --upgrade
    pip install django-polymorphic --upgrade
    pip install django --upgrade
    pip install pillow --upgrade
    ./manage.py makemigrations
    ./manage.py migrate

The following must be removed/commented out from settings.py: :

    TEMPLATE_DIRS
    TEMPLATE_DEBUG
    TEMPLATE_LOADERS
    TEMPLATE_CONTEXT_PROCESSORS

The following needs to be added to settings.py: :

    TEMPLATES  = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
    ]

Once all these steps are completed your installation of DefectDojo will
be running under Django 1.11
