## Run with Docker Compose

Docker compose is not intended for production use.
If you want to deploy a containerized DefectDojo to a production environment,
use the [Helm and Kubernetes](KUBERNETES.md) approach.

### Setup via Docker Compose

If you start your DefectDojo instance on Docker Compose for the first time, just
run `docker-compose up`.

Navigate to <http://localhost:8080> where you can log in with username admin.
To find out the admin user’s password, check the very beginning of the console
output of the initializer container.

If you ran DefectDojo with compose before and you want to prevent the
initializer container from running again, define an environment variable
DD_INITIALIZE=false to prevent re-initialization.

### Clean up Docker Compose

```zsh
docker-compose down --volumes
```
