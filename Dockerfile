FROM ubuntu:16.04
MAINTAINER Matt Tesauro <matt.tesauro@owasp.org>

# Create a single Docker image running DefectDojo and all dependencies

# Update and install basic requirements;
# Install mysql-server already at this place, since we want to avoid interactivity
# Also: create the application user
RUN apt-get update \
    && apt-get install -y sudo git expect wget \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server \
    && adduser --disabled-password --gecos "DefectDojo" dojo

# Give the app user sudo permissions and switch executing user
ADD ./docker/etc/dojo_sudo /etc/sudoers.d/
USER dojo:dojo

# Add the application files and start the setup
ADD --chown=dojo:dojo . /opt/django-DefectDojo
WORKDIR /opt/django-DefectDojo
ENV AUTO_DOCKER=yes
RUN ./setup.bash

# Install wkhtmltox
RUN wget -O /tmp/wkhtmltox.tar.xz https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.4/wkhtmltox-0.12.4_linux-generic-amd64.tar.xz \
    && tar xvfJ /tmp/wkhtmltox.tar.xz -C /tmp \
    && sudo chown root:root /tmp/wkhtmltox/bin/wkhtmltopdf \
    && sudo cp /tmp/wkhtmltox/bin/wkhtmltopdf /usr/local/bin/wkhtmltopdf

# Start the DB server and rund the app
ENTRYPOINT sudo service mysql start \
    && celery -A dojo worker -l info --concurrency 3 >> /opt/django-DefectDojo/worker.log 2>&1 & \
    && celery beat -A dojo -l info  >> /opt/django-DefectDojo/beat.log 2>&1 & \
    && python manage.py runserver 0.0.0.0:8000 >> /opt/django-DefectDojo/dojo.log 2>&1
