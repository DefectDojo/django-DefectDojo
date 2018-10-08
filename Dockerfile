FROM ubuntu:16.04
RUN apt-get update \
    && apt-get install -y sudo git expect wget \
    && apt-get install -y curl vim \
    && apt-get install -y iputils-ping procps \
    && apt-get install -y mysql-client percona-toolkit \ 
    && apt-get install -y python-pip libmysqlclient-dev \
    && apt-get install -y npm nodejs\
    && npm install -g yarn \
    && ln -s /usr/bin/nodejs /usr/bin/node

# Add the application files and start the setup
RUN mkdir /django-DefectDojo
ADD requirements.txt /django-DefectDojo
WORKDIR /django-DefectDojo
RUN pip install -r requirements.txt

# Install wkhtmltopdf
RUN wget -O /tmp/wkhtmltox.deb https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.5/wkhtmltox_0.12.5-1.xenial_amd64.deb \
    && apt install -y /tmp/wkhtmltox.deb \
    && rm /tmp/wkhtmltox.deb
