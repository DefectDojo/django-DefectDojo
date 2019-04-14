# Run with Docker Compose

Docker compose is not intended for production use.
If you want to deploy a containerized DefectDojo to a production environment,
use the [Helm and Kubernetes](KUBERNETES.md) approach.

## Prerequisites
**NOTE:** Installing with docker-compose requires at least docker 18.09.4 and docker-compose 1.24.0. See "Checking Docker versions" below for version errors during running docker-compose.


## Setup via Docker Compose - introduction

DefectDojo needs several docker images to run. Two of them depend on DefectDojo code:

*  django image
*  nginx image

The nginx image is build based on the django image.

Before running the application, it's advised to build local images to make sure that you'll be working on images consistent with your current code base.
When running the application without building images, the application will run based on: 
*  a previously locally built image if it exists
*  else the image pulled from dockerhub
    *  https://hub.docker.com/r/defectdojo/defectdojo-django
    *  https://hub.docker.com/r/defectdojo/defectdojo-nginx


## Setup via Docker Compose - building and running the application
### Building images

To build images and put them in your local cache, run:

```zsh
docker-compose build
```

To build a single image, run: 

```zsh
docker-compose build django
```
or

```
docker-compose build nginx
```


### Run with Docker compose in release mode
To run the application based on previously built image (or based on dockerhub images if none was locally built), run: 

```zsh
docker-compose -f docker-compose_base.yml up
```

The -f argument makes docker-compose ignore the docker-compose.override.yml file.

In this setup, you need to rebuild django and/or nginx images after each code change and restart the containers 


### Run with Docker compose in development mode with hot-reloading

For development, use: 

```zsh
docker-compose up
```

This will run the application based on merged configurations from docker-compose.yml and docker-compose.override.yml (which holds the dev-specific configuration).

*  Volumes are mounted to synchronize between the host and the containers :
    *  static resources (nginx container)
    *  python code (django container) . 

*  The `--py-autoreload 1` parameter in entrypoint-uwsgi-dev.sh will make uwsgi handle python hot-reloading. 

To update changes in static ressources, served by nginx, just refresh the browser with ctrl + F5 

### Access the application
Navigate to the container directly, <http://localhost:8080>

The initializer container can be disabled by exporting: `export DD_INITIALIZE=false`

Navigate to <http://localhost:8080> where you can log in with username admin.
To find out the admin user’s password, check the very beginning of the console
output of the initializer container, typically name 'django-defectdojo_initializer_1', or run the following:

```zsh
container_id=(`docker ps -a \
--filter "name=django-defectdojo_initializer_1" \
| awk 'FNR == 2 {print $1}'`) && \
docker logs $container_id 2>&1 | grep "Admin password:"
```

or:

```zsh
docker logs django-defectdojo_initializer_1
```

If you ran DefectDojo with compose before and you want to prevent the
initializer container from running again, define an environment variable
DD_INITIALIZE=false to prevent re-initialization.

### Versioning
In order to use a specific version when building the images and running the containers, set the environment with 
*  For the nginx image: `NGINX_VERSION=x.y.z`
*  For the django image: `DJANGO_VERSION=x.y.z`

Building will tag the images with "x.y.z", then you can run the application based on a specific tagged images.

Tags can be verified with: 
*  Image tag: 

```
$ docker images
REPOSITORY                     TAG                 IMAGE ID            CREATED             SIZE
defectdojo/defectdojo-nginx    1.0.0               bc9c5f7bb4e5        About an hour ago   191MB
```

Running container tag:

``` 
$ docker ps
CONTAINER ID        IMAGE                                 COMMAND                  CREATED             STATUS              PORTS                                NAMES
aedc404d6dee        defectdojo/defectdojo-nginx:1.0.0     "/entrypoint-nginx.sh"   2 minutes ago       Up 2 minutes        80/tcp, 0.0.0.0:8080->8080/tcp       django-defectdojo_nginx_1
```




### Clean up Docker Compose

Removes all containers

```zsh
docker-compose down
```

Removes all containers, networks and the database volume

```zsh
docker-compose down --volumes
```

## Checking Docker versions

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

Follow [Dockers' documentation](https://docs.docker.com/install/) for your OS to get the lastest version of Docker. For the docker command, most OSes have a built-in update mechanism like "apt upgrade".

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

# Download and install lastest docker compose
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
