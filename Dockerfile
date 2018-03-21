FROM ubuntu:16.04
MAINTAINER Matt Tesauro <matt.tesauro@owasp.org>

# Create a single Docker running DefectDojo and all dependencies

ADD . /opt/django-DefectDojo

RUN apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y mysql-server sudo git expect wget \
    && usermod -d /var/lib/mysql/ mysql \
    && service mysql start \
    && cd /opt \
    && export AUTO_DOCKER=yes \
    && /opt/django-DefectDojo/setup.bash \
    && cd /tmp \
    && wget https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.4/wkhtmltox-0.12.4_linux-generic-amd64.tar.xz \
    && tar xvfJ wkhtmltox-0.12.4_linux-generic-amd64.tar.xz \
    && sudo chown root:root wkhtmltox/bin/wkhtmltopdf \
    && sudo cp wkhtmltox/bin/wkhtmltopdf /usr/local/bin/wkhtmltopdf \
    && service mysql stop

WORKDIR /opt/django-DefectDojo

ENTRYPOINT docker/entrypoint.sh
