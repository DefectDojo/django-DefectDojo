FROM ubuntu:16.04 as base
MAINTAINER Matt Tesauro <matt.tesauro@owasp.org>, Aaron Weaver <aaron.weaver@owasp.org>

# # # Create a docker image for DefectDojo and all dependencies

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
ADD ./docker/etc/dojo_sudo /etc/sudoers.d/
# Start DefectDojo Services
CMD entrypoint_scripts/run/startup-docker.bash

########## Stage: release ##########
FROM dev-mysql-self-contained as release
RUN ./setup-docker.bash -y release
USER dojo
CMD gunicorn --bind 0.0.0.0:$PORT wsgi
