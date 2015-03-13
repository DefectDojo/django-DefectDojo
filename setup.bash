#!/bin/bash

# Get MySQL details
function get_db_details() {
    read -p "MySQL user (should already exist): " SQLUSER
    stty -echo
    read -p "Password for user: " SQLPWD; echo
    stty echo
    read -p "Database name (should NOT exist): " DBNAME

    echo

    if mysql -fs -u$SQLUSER -p$SQLPWD $DBNAME >/dev/null 2>&1 </dev/null; then
        echo "Database $DBNAME already exists!"
        echo 
        read -p "Drop database $DBNAME? [Y/n] " DELETE
        if [[ ! $DELETE =~ ^[nN]$ ]]; then
            mysqladmin -f --user=$SQLUSER --password=$SQLPWD drop $DBNAME 
            mysqladmin --user=$SQLUSER --password=$SQLPWD create $DBNAME 
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

# Make sure we're not running as root
if [[ $EUID = 0 ]]; then
    echo "ERROR: Refusing to run as root. Please run again as another user."
    exit 1;
fi

echo "Welcome to TestTrack! This is a quick script to get you up and running."
echo
echo "NEED SUDO PRIVILEGES FOR NEXT STEPS!"
echo
echo "Attempting to install required packages..."
echo


# Set up packages via Yum / APT

YUM_CMD=$(which yum)
APT_GET_CMD=$(which apt-get)

if [[ ! -z $YUM_CMD ]]; then
	sudo yum install gcc libmysqlclient-dev python-devel mysql-server mysql-devel mysql-python -y
elif [[ ! -z $APT_GET_CMD ]]; then
    sudo apt-get install gcc libssl-dev python-dev libmysqlclient-dev python-pip mysql-server -y
else
	echo "ERROR! OS not supported. Try the Vagrant option."
	exit 1;
fi

echo 

get_db_details

SECRET=`cat /dev/urandom | tr -dc "a-zA-Z0-9" | head -c 128`

unset HISTFILE
cp tracker/settings.dist.py tracker/settings.py

# Save MySQL details in settings file
sed -i  "s/MYSQLUSER/$SQLUSER/g" tracker/settings.py
sed -i  "s/MYSQLPWD/$SQLPWD/g" tracker/settings.py
sed -i  "s/MYSQLDB/$DBNAME/g" tracker/settings.py
sed -i  "s#TRACKERDIR#$PWD/tracker#g" tracker/settings.py
sed -i  "s/TRACKERSECRET/$SECRET/g" tracker/settings.py

# Detect if we're in a a virtualenv
if python -c 'import sys; print sys.real_prefix' 2>/dev/null; then
    python setup.py install
    python manage.py syncdb
    python manage.py migrate
else
    sudo python setup.py install
    sudo python manage.py syncdb
    sudo python manage.py migrate
fi


echo "=============================================================================="
echo
echo "SUCCESS! Now edit your settings.py file in the 'tracker' directory to complete the installation."
echo
echo "When you're ready to start the TestTrack server, type 'python manage.py runserver' in this directory."
