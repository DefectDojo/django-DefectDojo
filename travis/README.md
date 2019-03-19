# Travis Testing

All builds must pass
[Travis](https://travis-ci.org/DefectDojo/django-DefectDojo) testing before
merging into the DefectDojo branches.

## Build Process
The build process uses the .travis file located in the root directory and the
following scripts are called:

1. [before-install.sh](before-install.sh): Updates and installs socat
2. [before-script.sh](before-script.sh): Setups and installs minikube
3. [script.sh](script.sh): Main scripts, builds local containers, runs helms and
deploys to minikube.
4. [after-success-script.sh](after-success-script.sh): Pushes built containers
to docker hub.
