
FROM ubuntu:16.04
MAINTAINER Matt Tesauro <matt.tesauro@owasp.org<mailto:matt.tesauro@owasp.org>>

# Create a single Docker running DefectDojo and all dependencies

RUN apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y mysql-server sudo git expect \
    && usermod -d /var/lib/mysql/ mysql \
    && service mysql start \
    && cd /opt \
    && git clone https://github.com/OWASP/django-DefectDojo.git \
    && export AUTO_DOCKER=yes \
    && /opt/django-DefectDojo/setup.bash \
    && service mysql stop

WORKDIR /opt/django-DefectDojo

CMD chown -R mysql:mysql /var/lib/mysql /var/run/mysqld \
    && service mysql start \
    && python manage.py runserver 0.0.0.0:8000<http://0.0.0.0:8000>
