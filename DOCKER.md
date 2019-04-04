# Run with Docker Compose

Docker compose is not intended for production use.
If you want to deploy a containerized DefectDojo to a production environment,
use the [Helm and Kubernetes](KUBERNETES.md) approach.

## Setup via Docker Compose

If you start your DefectDojo instance on Docker Compose for the first time, just
run `docker-compose up`.

Navigate to <http://localhost:8080> where you can log in with username admin.
To find out the admin user’s password, check the very beginning of the console
output of the initializer container, typically name 'django-defectdojo_initializer_1', or run the following:

```zsh
container_id=(`docker ps -a \
--filter "name=django-defectdojo_initializer_1" \
| awk 'FNR == 2 {print $1}'`) && \
docker logs $container_id 2>&1 | grep "Admin password:"
```

If you ran DefectDojo with compose before and you want to prevent the
initializer container from running again, define an environment variable
DD_INITIALIZE=false to prevent re-initialization.

### Develop with Docker Compose

For developing the easiset way to make changes is to startup DefectDojo in debug by running `docker-compose -f docker-compose.yml up`. This starts the DefectDojo (uwsgi) container with manage.py and shares the local source directory so that changes to the code immediately restart the process.

Navigate to the container directly, <http://localhost:8000>

The initializer container can be disabled by exporting: `export DD_INITIALIZE=false`

### Build Images Locally

Build the docker containers locally for testing purposes.

```zsh
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
