FROM appsecpipeline/dojo-base

#Create the dojo user
RUN useradd -m dojo

#Change to the dojo user
USER dojo

#Add DefectDojo
ADD . /django-DefectDojo

#Set working directory
WORKDIR /django-DefectDojo

#Run the setup script
RUN bash docker/docker-startup.bash setup

CMD bash docker/docker-startup.bash
