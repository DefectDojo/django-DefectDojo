#!/bin/sh

sudo apt-get -y update
sudo apt-get -y install socat curl python-software-properties
curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -
sudo apt-get install nodejs
sudo npm install -g snyk