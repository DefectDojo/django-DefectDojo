#!/bin/sh

sudo apt-get -y update
sudo apt-get -y install socat curl python3-software-properties
python3 get-pip.py

# Install Snyk
curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -
sudo apt-get install nodejs
sudo npm install -g snyk

# Install Deployment
sudo curl https://cli-assets.heroku.com/install-ubuntu.sh | sh
