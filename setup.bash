#!/bin/bash

# Get MySQL details
function get_db_details() {
    read -p "MySQL user (should already exist): " SQLUSER
    stty -echo
    read -p "Password for user: " SQLPWD; echo
    stty echo
    read -p "Database name (should NOT exist): " DBNAME

    echo

    if mysql -fs -u"$SQLUSER" -p"$SQLPWD" "$DBNAME" >/dev/null 2>&1 </dev/null; then
        echo "Database $DBNAME already exists!"
        echo
        read -p "Drop database $DBNAME? [Y/n] " DELETE
        if [[ ! $DELETE =~ ^[nN]$ ]]; then
            mysqladmin -f --user="$SQLUSER" --password="$SQLPWD" drop "$DBNAME"
            mysqladmin --user="$SQLUSER" --password="$SQLPWD" create "$DBNAME"
        else
            echo "Error! Must supply an empty database to proceed."
            echo
            get_db_details
        fi
    else
        if mysqladmin --user=$SQLUSER --password=$SQLPWD create $DBNAME; then
            echo "Created database $DBNAME."
        else
            echo "Error! Failed to create database $DBNAME. Check your credentials."
            echo
            get_db_details
        fi
    fi
}

echo "Welcome to DefectDojo! This is a quick script to get you up and running."
echo
echo "NEED SUDO PRIVILEGES FOR NEXT STEPS!"
echo
echo "Attempting to install required packages..."
echo


# Set up packages via Yum / APT

YUM_CMD=$(which yum)
APT_GET_CMD=$(which apt-get)
BREW_CMD=$(which brew)

if [[ ! -z "$YUM_CMD" ]]; then
    sudo curl -sL https://rpm.nodesource.com/setup | sudo bash -
	sudo yum install gcc libmysqlclient-dev python-devel mysql-server mysql-devel MySQL-python python-setuptools python-pip nodejs wkhtmltopdf npm -y
	sudo yum groupinstall 'Development Tools'
elif [[ ! -z "$APT_GET_CMD" ]]; then
    sudo apt-get install libjpeg-dev gcc libssl-dev python-dev libmysqlclient-dev python-pip mysql-server nodejs-legacy wkhtmltopdf npm -y
elif [[ ! -z "$BREW_CMD" ]]; then
    brew install gcc openssl python mysql node npm Caskroom/cask/wkhtmltopdf
else
	echo "ERROR! OS not supported. Try the Vagrant option."
	exit 1;
fi

# bower install
sudo npm install -g bower

echo

get_db_details

unset HISTFILE

if [[ ! -z "$BREW_CMD" ]]; then
	LC_CTYPE=C
fi

SECRET=`cat /dev/urandom | LC_CTYPE=C tr -dc "a-zA-Z0-9" | head -c 128`

cp dojo/settings.dist.py dojo/settings.py

# Save MySQL details in settings file
if [[ ! -z $BREW_CMD ]]; then
  sed -i ''  "s/MYSQLHOST/localhost/g" dojo/settings.py
  sed -i ''  "s/MYSQLPORT/3306/g" dojo/settings.py
  sed -i ''  "s/MYSQLUSER/$SQLUSER/g" dojo/settings.py
  sed -i ''  "s/MYSQLPWD/$SQLPWD/g" dojo/settings.py
  sed -i ''  "s/MYSQLDB/$DBNAME/g" dojo/settings.py
  sed -i ''  "s#DOJODIR#$PWD/dojo#g" dojo/settings.py
  sed -i ''  "s/DOJOSECRET/$SECRET/g" dojo/settings.py
  sed -i ''  "s#BOWERDIR#$PWD/components#g" dojo/settings.py
  sed -i ''  "s#DOJO_MEDIA_ROOT#$PWD/media/#g" dojo/settings.py
  sed -i ''  "s#DOJO_STATIC_ROOT#$PWD/static/#g" dojo/settings.py
else
  sed -i  "s/MYSQLHOST/localhost/g" dojo/settings.py
  sed -i  "s/MYSQLPORT/3306/g" dojo/settings.py
  sed -i  "s/MYSQLUSER/$SQLUSER/g" dojo/settings.py
  sed -i  "s/MYSQLPWD/$SQLPWD/g" dojo/settings.py
  sed -i  "s/MYSQLDB/$DBNAME/g" dojo/settings.py
  sed -i  "s#DOJODIR#$PWD/dojo#g" dojo/settings.py
  sed -i  "s/DOJOSECRET/$SECRET/g" dojo/settings.py
  sed -i  "s#BOWERDIR#$PWD/components#g" dojo/settings.py
  sed -i  "s#DOJO_MEDIA_ROOT#$PWD/media/#g" dojo/settings.py
  sed -i  "s#DOJO_STATIC_ROOT#$PWD/static/#g" dojo/settings.py
fi

# Detect Python version
PYV=`python -c "import sys;t='{v[0]}.{v[1]}'.format(v=list(sys.version_info[:2]));sys.stdout.write(t)";`
if [[ "$PYV"<"2.7" ]]; then
    echo "ERROR: DefectDojo requires Python 2.7+"
    exit 1;
else
    echo "Leaving Django 1.8.10 requirement"
fi

# Detect if we're in a a virtualenv
if python -c 'import sys; print sys.real_prefix' 2>/dev/null; then
    pip install .
    python manage.py makemigrations dojo
    python manage.py makemigrations
    python manage.py migrate --fake
    python manage.py loaddata product_type
    python manage.py loaddata test_type
    python manage.py loaddata development_environment
    python manage.py installwatson
    python manage.py buildwatson
else
    sudo pip install .
    sudo python manage.py makemigrations dojo
    sudo python manage.py makemigrations
    sudo python manage.py migrate --fake
    sudo python manage.py loaddata product_type
    sudo python manage.py loaddata test_type
    sudo python manage.py loaddata development_environment
    sudo python manage.py installwatson
    sudo python manage.py buildwatson
fi

if [[ "$USER" == "root" ]]; then
    cd components && bower install --allow-root && cd ..
else
    cd components && bower install && cd ..
fi

# Detect if we're in a a virtualenv
if python -c 'import sys; print sys.real_prefix' 2>/dev/null; then
    python manage.py collectstatic --noinput
else
    sudo python manage.py collectstatic --noinput
fi


echo "=============================================================================="
echo
echo "SUCCESS! Now edit your settings.py file in the 'dojo' directory to complete the installation."
echo
echo "We suggest you consider changing the following defaults:"
echo
echo "    DEBUG = True  # you should set this to False when you are ready for production."
echo "    Uncomment the following lines if you enabled SSL/TLS on your server:"
echo "        SESSION_COOKIE_SECURE = True"
echo "        CSRF_COOKIE_SECURE = True"
echo "        SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTOCOL', 'https')"
echo "        SECURE_SSL_REDIRECT = True"
echo "        SECURE_BROWSER_XSS_FILTER = True"
echo "        django.middleware.security.SecurityMiddleware"
echo
echo "When you're ready to start the DefectDojo server, type in this directory:"
echo
echo "    python manage.py runserver"
echo
echo "Note: If git cannot connect using the git:// protocol when downloading bower artifacts, you can run the command "
echo "below to switch over to https://"
echo "          git config --global url."https://".insteadOf git://"
