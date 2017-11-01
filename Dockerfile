FROM ubuntu:16.04
MAINTAINER Matt Tesauro <matt.tesauro@owasp.org>

# Create a single Docker running DefectDojo and all dependencies

RUN apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y mysql-server sudo git expect wget \
    && usermod -d /var/lib/mysql/ mysql \
    && service mysql start \
    && cd /opt \
    && git clone https://github.com/OWASP/django-DefectDojo.git \
    && export AUTO_DOCKER=yes \
    && /opt/django-DefectDojo/setup.bash \
    && cd /tmp \
    && wget https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.4/wkhtmltox-0.12.4_linux-generic-amd64.tar.xz \
    && tar xvfJ wkhtmltox-0.12.4_linux-generic-amd64.tar.xz \
    && sudo chown root:root wkhtmltox/bin/wkhtmltopdf \
    && sudo cp wkhtmltox/bin/wkhtmltopdf /usr/local/bin/wkhtmltopdf \
    && service mysql stop 

WORKDIR /opt/django-DefectDojo

ENTRYPOINT chown -R mysql:mysql /var/lib/mysql /var/run/mysqld \
    && service mysql start \
    && su - dojo -c "cd /opt/django-DefectDojo && celery -A dojo worker -l info --concurrency 3 >> /opt/django-DefectDojo/worker.log 2>&1 &" \
    && su - dojo -c "cd /opt/django-DefectDojo && celery beat -A dojo -l info  >> /opt/django-DefectDojo/beat.log 2>&1 &" \
    && su - dojo -c "cd /opt/django-DefectDojo && python manage.py runserver 0.0.0.0:8000 >> /opt/django-DefectDojo/dojo.log 2>&1"

