FROM ubuntu:16.04

RUN apt-get update \
    && apt-get install -y sudo git expect wget python-pip virtualenv \
    && apt-get install -y curl apt-transport-https \
    && curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
RUN echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list
RUN curl -sL https://deb.nodesource.com/setup_6.x | sudo -E bash
RUN apt-get update \
    && apt-get install -y apt-transport-https libjpeg-dev gcc libssl-dev python-dev python-pip nodejs yarn wkhtmltopdf build-essential \
    && apt-get install -y libmysqlclient-dev mysql-client

