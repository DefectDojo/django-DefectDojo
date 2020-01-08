# # Simple and fast testing suite
# FROM python:3.5.7-buster@sha256:4598d4365bb7a8628ba840f87406323e699c4da01ae6f926ff33787c63230779 as build
# EXPOSE 5000
# CMD ["ping", "0.0.0.0"]

FROM ubuntu:18.04
FROM python:3.5.7-buster@sha256:4598d4365bb7a8628ba840f87406323e699c4da01ae6f926ff33787c63230779 as build
USER root

# SETUP.BASH INSTALL

# Install MySQL, virtualenv, and nginx
RUN \
    apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y install \
        mariadb-server \
        nginx \
        uwsgi-plugin-python3 \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists && \
    /etc/init.d/mysql start && \
    pip install virtualenv uwsgi

# Create virtualenv and download Dojo
RUN \ 
    cd /opt && \ 
    virtualenv dojo && \ 
    cd /opt/dojo && \ 
    git clone -b dev https://github.com/DefectDojo/django-DefectDojo.git

# Activate virtualenv and install dojo
RUN \
    cd /opt/dojo && \
    . ./bin/activate && \
    cd django-DefectDojo && \
    DEMO=true PROMPT=false INSTALL_TYPE="Dev Install" ./setup/setup.bash && \
    python3 manage.py loaddata .github/demo/defect_dojo_sample_data.json

# Include nginx config
RUN \
    cp /opt/dojo/django-DefectDojo/.github/demo/nginx.conf /etc/nginx/sites-enabled/ && \
    rm /etc/nginx/sites-enabled/default && \
    nginx -t

EXPOSE 5000
CMD ["/opt/dojo/django-DefectDojo/.github/demo/dev-runner"]
