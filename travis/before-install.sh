#!/bin/sh

sudo apt-get -y update
sudo apt-get -f install
sudo apt-get -y install socat curl python3-software-properties conntrack
sudo apt-get install python3-pip python3-setuptools python3-wheel
sudo -H pip3 install -U setuptools pip
sudo pip3 --version

# Install Snyk
curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -
sudo apt-get install nodejs
sudo npm install -g snyk


# Install Deployment
# Disabled because it breaks the build currently due to an error. It's not used currently.
# sudo curl https://cli-assets.heroku.com/install-ubuntu.sh | sh
