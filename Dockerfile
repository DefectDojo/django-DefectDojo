FROM ubuntu:latest as base
MAINTAINER Matt Tesauro <matt.tesauro@owasp.org>, Aaron Weaver <aaron.weaver@owasp.org>

# Multi-stage build for DefectDojo
# Stage 1: base
# Creates the base image with DefectDojo and Django
#
# Stage 2: dev-mysql-self-contained
# Creates an all in one with mysql for travis and dev testing
#
# Stage 3: release
# DefectDojo app only with depenencies and for use with an external DB
#
# To build MySQL:
# docker build --target dev-mysql-self-contained -t defectdojo-dev-mysql-self-contained .
#
# To build release (no DB):
# docker build --target release -t defectdojo-release .

# Create the application user;
RUN adduser --disabled-password --gecos "DefectDojo" dojo

# Add the application files and start the setup
ADD --chown=dojo:dojo . /opt/django-DefectDojo
WORKDIR /opt/django-DefectDojo

# Update and install basic requirements
RUN ./setup-docker.bash -y dependencies

########## Stage: dev-mysql-self-contained ##########
FROM base as dev-mysql-self-contained
RUN ./setup-docker.bash -y db -d MYSQL
# Give the app user sudo permissions and switch executing user
ADD ./docker/dojo_sudo /etc/sudoers.d/
USER dojo:dojo
# Start DefectDojo Services
CMD entrypoint_scripts/run/startup-docker.bash

########## Stage: release ##########
FROM dev-mysql-self-contained as release
RUN ./setup-docker.bash -y release
RUN chmod +x docker/entrypoint.sh
CMD docker/entrypoint.sh
