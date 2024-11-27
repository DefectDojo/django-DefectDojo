---
title: "Upgrading Guide"
description: "Release specific upgrading instructions"
draft: false
sidebar:
    collapsed: true
weight: -900000000
---

## Docker compose

When you deploy a vanilla docker compose, it will create a persistent
volume for your Postgres database. As long as your volume is there, you
should not lose any data.

### Using docker images provided in DockerHub

If you\'re using `latest`, then you need to pre pull the `latest` from
DockerHub to update.

The generic upgrade method for docker compose are as follows:
-   Pull the latest version

    ``` {.sourceCode .bash}
    docker pull defectdojo/defectdojo-django:latest
    docker pull defectdojo/defectdojo-nginx:latest
    ```

-   If you would like to use a version other than the latest, specify the version (tag) you want to upgrade to:

    ``` {.sourceCode .bash}
    docker pull defectdojo/defectdojo-django:1.10.2
    docker pull defectdojo/defectdojo-nginx:1.10.2
    ```

-   If you would like to use alpine based images, you specify the version (tag) you want to upgrade to:

    ``` {.sourceCode .bash}
    docker pull defectdojo/defectdojo-django:1.10.2-alpine
    docker pull defectdojo/defectdojo-nginx:1.10.2-alpine
    ```

-   Go to the directory where your docker-compose.yml file lives
-   Stop DefectDojo: `./dc-stop.sh`
-   Re-start DefectDojo, allowing for container recreation:
    `./dc-up-d.sh`
-   Database migrations will be run automatically by the initializer.
    Check the output via `docker compose logs initializer` or relevant k8s command
-   If you have the initializer disabled (or if you want to be on the
    safe side), run the migration command:
    `docker compose exec uwsgi /bin/bash -c "python manage.py migrate"`

### Building your local images

If you build your images locally and do not use the ones from DockerHub,
the instructions are the same, with the caveat that you must build your images
first.
-   Pull the latest DefectDojo changes

    ``` {.sourceCode .bash}
    git fetch
    git pull
    git merge origin/master
    ```

Then replace the first step of the above generic upgrade method for docker compose with: `docker compose build`

## godojo installations

If you have installed DefectDojo on "iron" and wish to upgrade the installation, please see the [instructions in the repo](https://github.com/DefectDojo/godojo/blob/master/docs-and-scripts/upgrading.md).
