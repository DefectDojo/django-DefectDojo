FROM ubuntu:latest
LABEL maintainer "Matt Tesauro <matt.tesauro@owasp.org>"

RUN DEBIAN_FRONTEND=noninteractive apt-get update

# REVIEW: I think 'build-essential' contains git and gcc
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
    sudo \
    git \
    curl \
    expect \
    apt-transport-https \
    libjpeg-dev \
    gcc \
    libssl-dev \
    python-dev \
    python-pip \
    gunicorn \
    nodejs \
    wkhtmltopdf \
    build-essential \
    libmysqlclient-dev

# 'cmdtest' contains a conflicting 'yarn'
RUN apt-get remove cmdtest
RUN echo 'deb https://dl.yarnpkg.com/debian/ stable main' | tee /etc/apt/sources.list.d/yarn.list
RUN curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
RUN apt-get update
RUN apt-get install -y yarn

RUN adduser --disabled-password --gecos "DefectDojo" dojo
ADD ./docker/dojo_sudo /etc/sudoers.d/
USER dojo:dojo
ADD --chown=dojo:dojo . /opt/django-DefectDojo
WORKDIR /opt/django-DefectDojo
RUN sudo -H pip install .
RUN sudo -H pip install .[mysql]
RUN sudo -H pip install -r requirements.txt
RUN cd components && yarn

ADD --chown=dojo:dojo ./docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ADD --chown=dojo:dojo ./docker/wait-for-it.sh /wait-for-it.sh
RUN chmod +x /wait-for-it.sh
ENTRYPOINT /entrypoint.sh
