# Running with Docker Compose

The docker-compose.yml in this repo is not intended for production use without first customizing it to fit your specific situation.  Please consider the docker-compose.yml files are templates to create on that fits your needs.
Docker Compose is acceptable if you want to deploy a containerized DefectDojo to a production environment.
It is one of the supported [Default installation](setup/README.md) methods.

# Prerequisites
*  Docker version
    *  Installing with docker-compose requires at least docker 18.09.4 and docker-compose 1.24.0. See "Checking Docker versions" below for version errors during running docker-compose.
*  Proxies
    *  If you're behind a corporate proxy check https://docs.docker.com/network/proxy/ . 
*  Known issues
    * finding images only work in `dev` and `ptvsd` mode. Making them work in `release` mode requires modifications to the docker-compose configuration.

# Setup via Docker Compose - introduction

DefectDojo needs several docker images to run. Two of them depend on DefectDojo code:

*  django service - defectdojo/defectdojo-django image 
*  nginx service - defectdojo/defectdojo-nginx image

The nginx image is build based on the django image.

Before running the application, it's advised to build local images to make sure that you'll be working on images consistent with your current code base.
When running the application without building images, the application will run based on: 
*  a previously locally built image if it exists in the docker cache
*  else the images pulled from dockerhub
    *  https://hub.docker.com/r/defectdojo/defectdojo-django
    *  https://hub.docker.com/r/defectdojo/defectdojo-nginx


# Setup via Docker Compose - building and running the application
## Building images

To build images and put them in your local docker cache, run:

```zsh
docker-compose build
```

To build a single image, run: 

```zsh
docker-compose build uwsgi
```
or

```
docker-compose build nginx
```

> **_NOTE:_**  It's possible to add extra fixtures in folder "/docker/extra_fixtures".

## Run with Docker compose in release mode
To run the application based on previously built image (or based on dockerhub images if none was locally built), run: 

```zsh
docker/setEnv.sh release
docker-compose up
```

This will run the application based on docker-compose.yml only.

In this setup, you need to rebuild django and/or nginx images after each code change and restart the containers. 


## Run with Docker compose in development mode with hot-reloading

For development, use: 

```zsh
docker/setEnv.sh dev
docker-compose build
docker-compose up
```

This will run the application based on merged configurations from docker-compose.yml and docker-compose.override.dev.yml.

*  Volumes are mounted to synchronize between the host and the containers :
    *  static resources (nginx container)
    *  python code (uwsgi and celeryworker containers). 

*  The `--py-autoreload 1` parameter in entrypoint-uwsgi-dev.sh will make uwsgi handle python hot-reloading for the **uwsgi** container.
* Hot-reloading for the **celeryworker** container is not yet implemented. When working on deduplication for example, restart the celeryworker container with: 

```
docker-compose restart celeryworker
```

*  The mysql port is forwarded to the host so that you can access your database from outside the container. 

To update changes in static resources, served by nginx, just refresh the browser with ctrl + F5.


*Notes about volume permissions*

*If you run into permission issues with the mounted volumes, a way to fix this is changing `USER 1001` in Dockerfile.django to match your user uid and then rebuild the images. Get your user id with* 

```
id -u
```

## Run with Docker compose in development mode with ptvsd (remote debug)

If you want to be able to step in your code, you can activate ptvsd.Server.

You can launch your local dev instance of DefectDojo as

```zsh
docker/setEnv.sh ptvsd
docker-compose up
```

This will run the application based on merged configurations from docker-compose.yml and docker-compose.override.ptvsd.yml.

The default configuration assumes port 3000 by default for ptvsd.

### VS code
Add the following python debug configuration (You would have to install the `ms-python.python`. Other setup may work.)

```
  {
      "name": "Remote DefectDojo",
      "type": "python",
      "request": "attach",
      "pathMappings": [
          {
              "localRoot": "${workspaceFolder}",
              "remoteRoot": "/app"
          }
      ],
      "port": 3000,
      "host": "localhost"
  }
```

You can now launch the remote debug from VS Code, place your breakpoints and step through the code.

> At present, 2 caveats:
> - Static will not be present. You would have to `docker cp` them over from the nginx container
> - For some reason, the page loading may hang. You can stop the loading and reload, the page will ultimately appear.


## Access the application
Navigate to <http://localhost:8080> where you can log in with username admin.
To find out the admin password, check the very beginning of the console
output of the initializer container by running:

```zsh
docker-compose logs initializer | grep "Admin password:"
```

Make sure you write down the first password generated as you'll need it when re-starting the application.

## Option to change the password 
* If you dont have admin password use the below command to change the password. 
* After starting the container and open another tab in the same folder.  
* django-defectdojo_uwsgi_1 -- name obtained from running containers using ```zsh docker ps ``` command

```zsh
docker exec -it django-defectdojo_uwsgi_1 ./manage.py changepassword admin
```

# Logging
For docker-compose release mode the log level is INFO. In the other modes the log level is DEBUG. Logging is configured in `settings.dist.py` and can be tuned using a `local_settings.py`, see [template for local_settings.py](dojo/settings/template-local_settings). For example the deduplication logger can be set to DEBUG in a local_settings.py file:


```
LOGGING['loggers']['dojo.specific-loggers.deduplication']['level'] = 'DEBUG'
```

Or you can modify `settings.dist.py` directly, but this adds the risk of having conflicts when `settings.dist.py` gets updated upstream. 

```
          'dojo.specific-loggers.deduplication': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        }
```

## Debug Toolbar
In the `dojo/settings/template-local_settings.py` you'll find instructions on how to enable the [Django Debug Toolbar](https://github.com/jazzband/django-debug-toolbar).
This toolbar allows you to debug SQL queries, and shows some other interesting information.


# Exploitation, versioning
## Disable the database initialization
The initializer container can be disabled by exporting: `export DD_INITIALIZE=false`. 

This will ensure that the database remains unchanged when re-running the application, keeping your previous settings and admin password.

## Versioning
In order to use a specific version when building the images and running the containers, set the environment with 
*  For the nginx image: `NGINX_VERSION=x.y.z`
*  For the django image: `DJANGO_VERSION=x.y.z`

Building will tag the images with "x.y.z", then you can run the application based on a specific tagged images.

*  Tagged images can be seen with: 

```
$ docker images
REPOSITORY                     TAG                 IMAGE ID            CREATED             SIZE
defectdojo/defectdojo-nginx    1.0.0               bc9c5f7bb4e5        About an hour ago   191MB
```

*  This will show on which tagged images the containers are running:

``` 
$ docker ps
CONTAINER ID        IMAGE                                 COMMAND                  CREATED             STATUS              PORTS                                NAMES
aedc404d6dee        defectdojo/defectdojo-nginx:1.0.0     "/entrypoint-nginx.sh"   2 minutes ago       Up 2 minutes        80/tcp, 0.0.0.0:8080->8080/tcp       django-defectdojo_nginx_1
```


## Clean up Docker Compose

Removes all containers

```zsh
docker-compose down
```

Removes all containers, networks and the database volume

```zsh
docker-compose down --volumes
```

# Run with docker using https
## use your own  Credentials
To secure the application by https, follow those steps
*  Generate a private key without password
*  Generate a CSR (Certificate Signing Request)
*  Have the CSR signed by a certificate authority
*  Place the private key and the certificate under the nginx folder
*  copy your secrets into: 
```
        server_name                 your.servername.com;
        ssl_certificate             /etc/nginx/ssl/nginx.crt
        ssl_certificate_key        /etc/nginx/ssl/nginx.key;
```
*set the GENERATE_TLS_CERTIFICATE != True in the docker-compose.override.https.yml
* Protect your private key from other users: 
```
chmod 400 nginx/*.key
```

* Run defectDojo with: 
```
rm -f docker-compose.override.yml
ln -s docker-compose.override.https.yml docker-compose.override.yml
docker-compose up
```

## create Credentials on the fly
* you can generate a Certificate on the fly (without valid domainname etc.)

* Run defectDojo with: 
```
rm -f docker-compose.override.yml
ln -s docker-compose.override.https.yml docker-compose.override.yml
docker-compose up
```

The default https port is 8443.

To change the port:
- update `nginx.conf`
- update `docker-compose.override.https.yml` or set DD_PORT in the environment)
- restart the application

NB: some third party software may require to change the exposed port in Dockerfile.nginx as they use docker-compose declarations to discover which ports to map when publishing the application.


# Run the tests with docker
The unit-tests are under `dojo/unittests`

The integration-tests are under `tests`


## Running the unit-tests
This will run all unit-tests and leave the uwsgi container up: 

```
docker/setEnv.sh unit_tests
docker-compose up
```
Enter the container to run more tests:

```
docker-compose exec uwsgi bash
```
Rerun all the tests:

```
python manage.py test dojo.unittests --keepdb
```

Run all the tests from a python file. Example:

```
python manage.py test dojo.unittests.test_dependency_check_parser --keepdb
```

Run a single test. Example:

```
python manage.py test dojo.unittests.test_dependency_check_parser.TestDependencyCheckParser.test_parse_without_file_has_no_findings --keepdb
```

## Running the integration-tests
This will run all integration-tests and leave the containers up: 

```
docker/setEnv.sh integration_tests
docker-compose up
```

# Checking Docker versions

Run the following to determine the versions for docker and docker-compose:

```zsh
$ docker version
Client:
 Version:      17.09.0-ce
 API version:  1.32
 Go version:   go1.8.3
 Git commit:   afdb6d4
 Built:        Tue Sep 26 22:42:45 2017
 OS/Arch:      linux/amd64

Server:
 Version:      17.09.0-ce
 API version:  1.32 (minimum version 1.12)
 Go version:   go1.8.3
 Git commit:   afdb6d4
 Built:        Tue Sep 26 22:41:24 2017
 OS/Arch:      linux/amd64
 Experimental: false

$ docker-compose version
docker-compose version 1.18.0, build 8dd22a9
docker-py version: 2.6.1
CPython version: 2.7.13
OpenSSL version: OpenSSL 1.0.1t  3 May 2016
```

In this case, both docker (version 17.09.0-ce) and docker-compose (1.18.0) need to be updated.

Follow [Dockers' documentation](https://docs.docker.com/install/) for your OS to get the latest version of Docker. For the docker command, most OSes have a built-in update mechanism like "apt upgrade".

Docker Compose isn't packaged like Docker and you'll need to manually update an existing install if using Linux. For Linux, either follow the instructions in the [Docker Compose documentation](https://docs.docker.com/compose/install/) or use the shell script below. The script below will update docker-compose to the latest version automatically. You will need to make the script executable and have sudo privileges to upgrade docker-compose:

```zsh
#!/bin/bash

# Set location of docker-compose binary - shouldn't need to modify this
DESTINATION=/usr/local/bin/docker-compose

# Get latest docker-compose version
VERSION=$(curl --silent https://api.github.com/repos/docker/compose/releases/latest | jq .name -r)

# Output some info on what this is going to do
echo "Note: docker-compose version $VERSION will be downloaded from:"
echo "https://github.com/docker/compose/releases/download/${VERSION}/docker-compose-$(uname -s)-$(uname -m)"
echo "Enter sudo password to install docker-compose"

# Download and install latest docker compose
sudo curl -L https://github.com/docker/compose/releases/download/${VERSION}/docker-compose-$(uname -s)-$(uname -m) -o $DESTINATION
sudo chmod +x $DESTINATION

# Output new docker-compose version info
echo ""
docker-compose version
```

Running the script above will look like:

```zsh
$ vi update-docker-compose
$ chmod u+x update-docker-compose
$ ./update-docker-compose
Note: docker-compose version 1.24.0 will be downloaded from:
https://github.com/docker/compose/releases/download/1.24.0/docker-compose-Linux-x86_64
Enter sudo password to install docker-compose
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   617    0   617    0     0   1778      0 --:--:-- --:--:-- --:--:--  1778
100 15.4M  100 15.4M    0     0  2478k      0  0:00:06  0:00:06 --:--:-- 2910k

docker-compose version 1.24.0, build 0aa59064
docker-py version: 3.7.2
CPython version: 3.6.8
OpenSSL version: OpenSSL 1.1.0j  20 Nov 2018
```
