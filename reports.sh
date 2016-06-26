#!/bin/sh

sudo apt-get install -y openssl build-essential xorg libssl-dev
wget http://download.gna.org/wkhtmltopdf/0.12/0.12.3/wkhtmltox-0.12.3_linux-generic-amd64.tar.xz
tar xvfJ wkhtmltox-0.12.3_linux-generic-amd64.tar.xz
sudo chown root:root wkhtmltox/bin/wkhtmltopdf
sudo cp wkhtmltox/bin/wkhtmltopdf /usr/bin/wkhtmltopdf
