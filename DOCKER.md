# Run with Docker Compose

Docker compose is not intended for production use.
If you want to deploy a containerized DefectDojo to a production environment,
use the [Helm and Kubernetes](KUBERNETES.md) approach.

## Setup via Docker Compose

To start your DefectDojo instance on Docker Compose for the first time, just
run:

```zsh
. docker/aliases_release.sh
docker-compose up
```

or

```zsh
docker-compose -f docker-compose_base.yml -f docker-compose_uwsgi-release.yml up
```

This command will run the application based on images commited on dockerhub (or the last images built locally). If you need to be more up to date, see "Build images locally" below

**NOTE:** Installing with docker-compose requires the latest version of docker and docker-compose - at least docker 18.09.4 and docker-compose 1.24.0. See "Checking Docker versions" below for version errors during running docker-compose up.

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

### Develop with Docker Compose

For developing the easiset way to make changes is to startup DefectDojo in debug by running:

```zsh
. docker/aliases_dev.sh
docker-compose up
```

or

```zsh
docker-compose -f docker-compose_base.yml -f docker-compose_uwsgi-dev.yml up
```

This starts the DefectDojo (uwsgi) container with manage.py and shares the local source directory so that changes to the code immediately restart the process.

Navigate to the container directly, <http://localhost:8000>

The initializer container can be disabled by exporting: `export DD_INITIALIZE=false`

### Remote debug with pvstd

If you want to be able to step in your code, you can active ptvsd.Server. 

You can launch your local dev instance of DefectDojo as

```
$ docker-compose -f docker-compose_base.yml -f docker-compose_uwsgi-ptvsd.yml up
```

The default configuration assumes port 3000 by default.

#### VS code
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

### Build Images Locally

Build the docker containers locally for testing purposes.

```zsh
# Build Dev Compose
docker-compose build

or:

# Build images
docker build -t defectdojo/defectdojo-django -f Dockerfile.django .
docker build -t defectdojo/defectdojo-nginx -f Dockerfile.nginx .
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
