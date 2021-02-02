---
title: "Running in Production"
date: 2021-02-02T20:46:28+01:00
draft: false
---



Improving your docker-compose performance
-----------------------------------------

### Database

Run your database elsewhere. Tweak your docker-compose configuration to
that effect. If you don\'t, you cannot pretend to be running in
production.

### Instance size

{{% notice note %}}
Please read the paragraphs below about key processes tweaks.
{{% /notice %}}


Having taken the database to run elsewhere, the minimum recommendation
is:

-   2 vCPUs
-   8 GB of RAM
-   2 GB of disk space (remember, your database is not here \-- so
    basically, what you have for your O/S should do). You could allocate
    a different disk than your OS\'s for potential performance
    improvements.

### Key processes

Per <https://github.com/DefectDojo/django-DefectDojo/pull/2813>, it is
now easy to somewhat improve the uWSGI and celery worker performance.

#### uWSGI

By default (except in `ptvsd` mode for debug purposes), uWSGI will
handle 4 concurrent connections.

Based on your resource settings, you can tweak:

-   `DD_UWSGI_NUM_OF_PROCESSES` for the number of spawned processes.
    (default 2)
-   `DD_UWSGI_NUM_OF_THREADS` for the number of threads in these
    processes. (default 2)

For example, you may have 4 processes with 6 threads each, yielding 24
concurrent connections.

#### Celery worker

By default, a single mono-process celery worker is spawned. This is fine
until you start having many findings, and when async operations like
deduplication start to kick in. Eventually, it will starve your
resources and crawl to a halt, while operations continue to queue up.

The following variables will help a lot, while keeping a single celery
worker container.

-   `DD_CELERY_WORKER_POOL_TYPE` will let you switch to `prefork`.
    (default `solo`)

As you\'ve enabled [prefork]{.title-ref}, the following variables have
to be used. The default are working fairly well, see the
Dockerfile.django for in-file references.

-   `DD_CELERY_WORKER_AUTOSCALE_MIN` defaults to 2.
-   `DD_CELERY_WORKER_AUTOSCALE_MAX` defaults to 8.
-   `DD_CELERY_WORKER_CONCURRENCY` defaults to 8.
-   `DD_CELERY_WORKER_PREFETCH_MULTIPLIER` defaults to 128.

You can execute the following command to see the configuration:

`docker-compose exec celerybeat bash -c "celery -A dojo inspect stats"`
and see what is in effect.

Production with setup.bash
--------------------------

{{% notice warning %}}
From this point down, this page is slated to get a revamp
{{% /notice %}}


This guide will walk you through how to setup DefectDojo for running in
production using Ubuntu 16.04, nginx, and uwsgi.

**Install, Setup, and Activate Virtualenv**

Assumes running as root or using sudo command for the below.

``` {.sourceCode .console}
pip install virtualenv

cd /opt

virtualenv dojo

cd /opt/dojo

git clone https://github.com/DefectDojo/django-DefectDojo.git

useradd -m dojo

chown -R dojo /opt/dojo

source ./bin/activate
```

**Install Dojo**

{{% notice warning %}}
The setup.bash installation method will be EOL on 2020-12-31
{{% /notice %}}


``` {.sourceCode .console}
cd django-DefectDojo/setup

./setup.bash
```

**Install Uwsgi**

``` {.sourceCode .console}
pip install uwsgi
```

**Install WKHTML**

from inside the django-DefectDojo/ directory execute:

``` {.sourceCode .console}
./reports.sh
```

**Disable Debugging**

Using the text-editor of your choice, change `DEBUG` in
django-DefectDojo/dojo/settings/settings.py to:

``` {.sourceCode .console}
`DEBUG = False`
```

**Configure external database**

If you host your DefectDojo into AWS and you decide to use their managed
database service (AWS RDS), you will have to do the following
configuration updates:

1)  [Download the root
    certificate](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html)
    to encrypt traffic between DefectDojo and the database
2)  Update your Dockerfile to add the SSL certificate to the container

``` {.sourceCode .console}
COPY rds-ca-2019-root.pem /etc/ssl/certs/rds-ca-2019-root.pem
```

3)  Update Django settings to use encrypted connection to the database
    (Changes highlighted below)

``` {.sourceCode .python}
DATABASES = {
    'default': env.db('DD_DATABASE_URL')
}
DATABASES['default']['OPTIONS'] = {
'ssl': {'ca': '/etc/ssl/certs/rds-ca-2019-root.pem'}
}
```

> else:
>
> :   
>
>     DATABASES = {
>
>     :   \'default\': {
>
4)  Update the environment variables for the database connection:
    *DD\_DATABASE\_URL* or *DD\_DATABASE\_HOST*, *DD\_DATABASE\_PORT*,
    *DD\_DATABASE\_NAME*, *DD\_DATABASE\_USER* and
    *DD\_DATABASE\_PASSWORD*.

Note: This configuration can be adapted to other cloud providers.

**Start Celery and Beats**

From inside the django-DefectDojo/ directory execute:

``` {.sourceCode .console}
celery -A dojo worker -l info --concurrency 3

celery beat -A dojo -l info
```

It is recommended that you daemonized both these processes with the
sample configurations found
[here](https://github.com/celery/celery/blob/3.1/extra/supervisord/celeryd.conf)
and
[here.](https://github.com/celery/celery/blob/3.1/extra/supervisord/celerybeat.conf)

However, for a quick setup you can use the following to run both in the
background

``` {.sourceCode .console}
celery -A dojo worker -l info --concurrency 3 &

celery beat -A dojo -l info &
```

**Start Uwsgi**

From inside the django-DefectDojo/ directory execute:

``` {.sourceCode .console}
uwsgi --socket :8001 --wsgi-file wsgi.py --workers 7
```

It is recommended that you use an Upstart job or a \@restart cron job to
launch uwsgi on reboot. However, if you're in a hurry you can use the
following to run it in the background:

``` {.sourceCode .console}
uwsgi --socket :8001 --wsgi-file wsgi.py --workers 7 &
```

**Making Defect Dojo start on boot**

Below we configure service files for systemd. The commands follow, the
config files are below the Nginx in the next section.

``` {.sourceCode .shell-session}
$ cd /etc/systemd/system/
$ sudo vi dojo.service
[contents below]

$ sudo systemctl enable dojo
$ sudo systemctl start dojo
$ sudo systemctl status dojo
[ensure it launched OK]

$ sudo vi celery-worker.service
[contents below]

$ sudo systemctl enable celery-worker
$ sudo systemctl start celery-worker
$ sudo systemctl status celery-worker
[ensure it launched OK]

$ sudo vi celery-beat.service
[contents below]

$ sudo systemctl enable celery-beat
$ sudo systemctl start celery-beat
$ sudo systemctl status celery-beat
[ensure it launched OK]
```

*NGINX Configuration*

Everyone feels a little differently about nginx settings, so here are
the barebones to add your to your nginx configuration to proxy uwsgi.
Make sure to modify the filesystem paths if needed:

``` {.sourceCode .nginx}
upstream django {
  server 127.0.0.1:8001;
}

server {
  listen 80;
  return 301 https://$host$request_uri;
}

server {
  listen 443;
  server_name <YOUR_SERVER_NAME>;

  client_max_body_size 500m; # To accommodate large scan files

  ssl_certificate           <PATH_TO_CRT>;
  ssl_certificate_key       <PATH_TO_KEY>;

  ssl on;

  <YOUR_SSL_SETTINGS> # ciphers, options, logging, etc

  location /static/ {
      alias   <PATH_TO_DOJO>/django-DefectDojo/static/;
  }

  location /media/ {
      alias   <PATH_TO_DOJO>/django-DefectDojo/media/;
  }

  location / {
      uwsgi_pass django;
      include     <PATH_TO_DOJO>/django-DefectDojo/wsgi_params;
  }
}
```

*Systemd Configuration Files*

dojo.service

``` {.sourceCode .ini}
[Unit]
Description=uWSGI instance to serve DefectDojo
Requires=nginx.service mysql.service
Before=nginx.service
After=mysql.service

[Service]
ExecStart=/bin/bash -c 'su - dojo -c "cd /opt/dojo/django-DefectDojo && source ../bin/activate && uwsgi --socket :8001 --wsgi-file wsgi.py --workers 7"'
Restart=always
RestartSec=3
#StandardOutput=syslog
#StandardError=syslog
SyslogIdentifier=dojo

[Install]
WantedBy=multi-user.target
```

celery-worker.service

``` {.sourceCode .ini}
[Unit]
Description=celery workers for DefectDojo
Requires=dojo.service
After=dojo.service

[Service]
ExecStart=/bin/bash -c 'su - dojo -c "cd /opt/dojo/django-DefectDojo && source ../bin/activate && celery -A dojo worker -l info --concurrency 3"'
Restart=always
RestartSec=3
#StandardOutput=syslog
#StandardError=syslog
SyslogIdentifier=celeryworker

[Install]
WantedBy=multi-user.target
```

celery-beat.service

``` {.sourceCode .ini}
[Unit]
Description=celery beat for DefectDojo
Requires=dojo.service
After=dojo.service

[Service]
ExecStart=/bin/bash -c 'su - dojo -c "cd /opt/dojo/django-DefectDojo && source ../bin/activate && celery beat -A dojo -l info"'
Restart=always
RestartSec=3
#StandardOutput=syslog
#StandardError=syslog
SyslogIdentifier=celerybeat

[Install]
WantedBy=multi-user.target
```

*That\'s it!*

*Monitoring*

To expose Django statistics for Prometheus, using the text-editor of
your choice, change `DJANGO_METRICS_ENABLED` to True in
django-DefectDojo/dojo/settings/settings.py to:

``` {.sourceCode .console}
`DJANGO_METRICS_ENABLED = True`
```

Or export `DD_DJANGO_METRICS_ENABLED` with the same value.

Prometheus endpoint than is available under the path:
`http://dd_server/django_metrics/metrics`
