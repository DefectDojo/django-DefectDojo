FROM ubuntu:wily

#Create the dojo user
RUN useradd -m dojo

#Change to the dojo user, necessary so that the volume is set to dojo
USER dojo

#Add DefectDojo
ADD . /django-DefectDojo

#Change to the root user
USER root

#Install requirements
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install build-essential libjpeg-dev gcc xorg nmap python-virtualenv wget npm build-essential nodejs-legacy python-dev python-pip nvi git libffi-dev libssl-dev libmysqlclient-dev mysql-client

#Run the setup script
RUN docker-setup.bash

#RUN chown -R dojo:dojo /django-DefectDojo

#Change back to the dojo user
USER dojo
