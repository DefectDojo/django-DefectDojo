#!/bin/bash
set -ev

# Docker Build
export DOJO_ADMIN_USER='admin'
export DOJO_ADMIN_PASSWORD='admin'
export CONTAINER_NAME=dojo
docker build -t $REPO .
# - docker run -e DOJO_ADMIN_USER=$DOJO_ADMIN_USER -e DOJO_ADMIN_PASSWORD=$DOJO_ADMIN_PASSWORD --name dojo -d -p 127.0.0.1:8000:8000 $REPO:${TRAVIS_COMMIT::8} bash /django-DefectDojo/docker/docker-startup.bash
docker run -d -p 127.0.0.1:8000:8000 --name=$CONTAINER_NAME $REPO
docker logs $CONTAINER_NAME
# Turn off Zap tests while re-configuring how they run
#- docker run -d --name zap --link $CONTAINER_NAME -p 127.0.0.1:8080:8080 -i owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
# Selenium and ZAP requirements
pip install selenium==2.53.6
pip install requests
pip install python-owasp-zap-v2.4
pip install prettytable
pip install bandit
wget -N https://chromedriver.storage.googleapis.com/2.33/chromedriver_linux64.zip -P ~/
unzip ~/chromedriver_linux64.zip -d ~/
rm ~/chromedriver_linux64.zip
sudo mv -f ~/chromedriver /usr/local/share/
sudo chmod +x /usr/local/share/chromedriver
sudo ln -s /usr/local/share/chromedriver /usr/local/bin/chromedriver
docker ps -a
docker logs $CONTAINER_NAME
echo "Checking to see if dojo is running"
curl http://127.0.0.1:8000/login?next=/

export DISPLAY=:99.0
sh -e /etc/init.d/xvfb start
sleep 3 # give xvfb some time to start
whereis chromedriver
export PATH=$PATH:/usr/local/bin/
python tests/check_status.py -v && python tests/smoke_test.py #&& python tests/zap.py

set +ev 
