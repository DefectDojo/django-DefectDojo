#!/bin/bash
set -ex

travis_fold() {
  local action=$1
  local name=$2
  echo -en "travis_fold:${action}:${name}\r"
}

travis_fold start travis_integration_install

# Docker Build
export DOJO_ADMIN_USER='admin'
export DD_ADMIN_PASSWORD='admin'
export DOJO_ADMIN_PASSWORD=$DD_ADMIN_PASSWORD
export CONTAINER_NAME=defect_dojo_integration
docker build --target dev-mysql-self-contained -t $REPO .
docker run -e DD_ADMIN_PASSWORD=$DD_ADMIN_PASSWORD -e ACTION=p -d -p 127.0.0.1:8000:8000 --name=$CONTAINER_NAME $REPO
docker logs $CONTAINER_NAME
# Turn off Zap tests while re-configuring how they run
#- docker run -d --name zap --link $CONTAINER_NAME -p 127.0.0.1:8080:8080 -i owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
# Selenium and ZAP requirements
pip install selenium
pip install requests
pip install python-owasp-zap-v2.4
pip install prettytable
wget -N https://chromedriver.storage.googleapis.com/2.37/chromedriver_linux64.zip -P ~/
unzip ~/chromedriver_linux64.zip -d ~/
rm ~/chromedriver_linux64.zip
sudo mv -f ~/chromedriver /usr/local/share/
sudo chmod +x /usr/local/share/chromedriver
sudo ln -s /usr/local/share/chromedriver /usr/local/bin/chromedriver
sleep 10
docker ps -a

docker logs $CONTAINER_NAME
travis_fold end container_log
echo "Checking to see if dojo is running"

# Check whether the container is running and came up as expected
set +e
STATE="inactive"
for i in $(seq 1 5); do
    curl -s -o /dev/null http://127.0.0.1:8000/login?next=/
    if [ "$?" == "0" ]; then
        STATE="running"
        break
    fi
    sleep 10
done
if [ "$STATE" != "running" ]; then
    docker ps -a
    docker logs $CONTAINER_NAME
    echo "Container did not come up properly" >&2
    exit 1
fi
set -e

export DISPLAY=:99.0
sh -e /etc/init.d/xvfb start
sleep 3 # give xvfb some time to start
whereis chromedriver
export PATH=$PATH:/usr/local/bin/

travis_fold end travis_integration_install

travis_fold start travis_integration_tests

python tests/check_status.py -v
python tests/smoke_test.py

travis_fold end travis_integration_tests
# python tests/zap.py

set +ex
