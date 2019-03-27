# Travis Testing

All builds must pass
[Travis](https://travis-ci.org/DefectDojo/django-DefectDojo) testing before
merging into the DefectDojo branches.

## Build Process

The build process uses the .travis file located in the root directory and the
following scripts are called:

1. [before-install.sh](before-install.sh): Updates and installs socat
2. [before-script.sh](before-script.sh): Setups and installs minikube
3. [script.sh](script.sh):

- Main script for building the project
- Builds two local containers for testing
- Starts minikube
- Runs Helm and installs DefectDojo to local minikube
- Validates the environment comes up correctly
- Runs unittests in [tests/*](../unitests)
- Runs flake8 test on merges into the dev branch
- Docker compose test

4.[after-success-script.sh](after-success-script.sh):

- Pushes built containers to docker hub.
- Weekly build containers from dev and master
- New tag or release creates a newly tagged versioned container
