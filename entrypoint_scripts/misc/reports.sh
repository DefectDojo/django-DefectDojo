#!/bin/sh

sudo apt-get install -y openssl build-essential xorg libssl-dev
wget https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.4/wkhtmltox-0.12.4_linux-generic-amd64.tar.xz
tar xvfJ wkhtmltox-0.12.4_linux-generic-amd64.tar.xz
sudo chown root:root wkhtmltox/bin/wkhtmltopdf
sudo cp wkhtmltox/bin/wkhtmltopdf /usr/bin/wkhtmltopdf
