FROM ubuntu:wily

#Add DefectDojo
ADD . /django-DefectDojo

#Install requirements
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install build-essential libjpeg-dev gcc xorg nmap python-virtualenv wget npm build-essential nodejs-legacy python-dev python-pip nvi git libffi-dev libssl-dev libmysqlclient-dev mysql-client

#Run the setup script
RUN /django-DefectDojo/docker/docker-setup.bash
