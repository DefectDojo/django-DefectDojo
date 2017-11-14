#!/bin/bash

NONE='\033[00m'
RED='\033[01;31m'
GREEN='\033[01;32m'
YELLOW='\033[01;33m'
PURPLE='\033[01;35m'
CYAN='\033[01;36m'
WHITE='\033[01;37m'
BOLD='\033[1m'
UNDERLINE='\033[4m'

#Supported databases
MYSQL=1
POSTGRES=2

function prompt_db_type() {
    read -p "Select database type: 1.) MySQL or 2.) Postgres: " DBTYPE
    if [ "$DBTYPE" == '1' ] || [ "$DBTYPE" == '2' ] ; then
    	echo "Setting up database"
    else
	echo "Please enter 1 or 2"
	prompt_db_type
    fi
}

# Get MySQL details
function get_db_details() {
    # Allow script to be called non-interactively using:
    # export AUTO_DOCKER=yes && /opt/django-DefectDojo/setup.bash
    if [ "$AUTO_DOCKER" != "yes" ]; then
        # Run interactively
        read -p "MySQL host: " SQLHOST
        read -p "MySQL port: " SQLPORT
        read -p "MySQL user (should already exist): " SQLUSER
        stty -echo
        read -p "Password for user: " SQLPWD; echo
        stty echo
        read -p "Database name (should NOT exist): " DBNAME
    else
        # Set the root password for mysql - install has it blank
        mysql -uroot -e "SET PASSWORD = PASSWORD('Cu3zehoh7eegoogohdoh1the');"
        # Default values for a automated Docker install
        echo "Setting default values for MySQL install"
        SQLHOST="localhost"
        SQLPORT="3306"
        SQLUSER="root"
        SQLPWD="Cu3zehoh7eegoogohdoh1the"
        DBNAME="dojodb"
    fi

    if mysql -fs -h "$SQLHOST" -P "$SQLPORT" -u"$SQLUSER" -p"$SQLPWD" "$DBNAME" >/dev/null 2>&1 </dev/null; then
        echo "Database $DBNAME already exists!"
        echo
        read -p "Drop database $DBNAME? [Y/n] " DELETE
        if [[ ! $DELETE =~ ^[nN]$ ]]; then
            mysqladmin -f --host="$SQLHOST" --port="$SQLPORT" --user="$SQLUSER" --password="$SQLPWD" drop "$DBNAME"
            mysqladmin    --host="$SQLHOST" --port="$SQLPORT" --user="$SQLUSER" --password="$SQLPWD" create "$DBNAME"
        else
            echo "Error! Must supply an empty database to proceed."
            echo
            get_db_details
        fi
    else
        if mysqladmin --host="$SQLHOST" --port="$SQLPORT" --user="$SQLUSER" --password="$SQLPWD" create $DBNAME; then
            echo "Created database $DBNAME."
        else
            echo "Error! Failed to create database $DBNAME. Check your credentials."
            echo
            get_db_details
        fi
    fi
}

function get_postgres_db_details() {
    read -p "Postgres host: " SQLHOST
    read -p "Postgres port: " SQLPORT
    read -p "Postgres user (should already exist): " SQLUSER
    stty -echo
    read -p "Password for user: " SQLPWD; echo
    stty echo
    read -p "Database name (should NOT exist): " DBNAME

    if [ "$( PGPASSWORD=$SQLPWD psql -h $SQLHOST -p $SQLPORT -U $SQLUSER -tAc "SELECT 1 FROM pg_database WHERE datname='$DBNAME'" )" = '1' ]
    then
        echo "Database $DBNAME already exists!"
        echo
        read -p "Drop database $DBNAME? [Y/n] " DELETE
        if [[ ! $DELETE =~ ^[nN]$ ]]; then
            PGPASSWORD=$SQLPWD dropdb $DBNAME -h $SQLHOST -p $SQLPORT -U $SQLUSER
            PGPASSWORD=$SQLPWD createdb $DBNAME -h $SQLHOST -p $SQLPORT -U $SQLUSER
        else
            read -p "Try and install anyway? [Y/n] " INSTALL
            if [[ $INSTALL =~ ^[nN]$ ]]; then
              echo
              get_postgres_db_details
            fi
        fi
    else
        PGPASSWORD=$SQLPWD createdb $DBNAME -h $SQLHOST -p $SQLPORT -U $SQLUSER
        if [ $? = 0 ]
        then
            echo "Created database $DBNAME."
        else
            echo "Error! Failed to create database $DBNAME. Check your credentials."
            echo
            get_postgres_db_details
        fi
    fi

}

echo "Welcome to DefectDojo! This is a quick script to get you up and running."
echo
# Allow script to be called non-interactively using:
# export AUTO_DOCKER=yes && /opt/django-DefectDojo/setup.bash
if [ "$AUTO_DOCKER" != "yes" ]; then
    prompt_db_type
else
    # Default to MySQL install
    DBTYPE=$MYSQL
fi
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
    curl -sL https://rpm.nodesource.com/setup | sudo bash -
	sudo yum install gcc python-devel python-setuptools python-pip nodejs wkhtmltopdf npm

        if [ "$DBTYPE" == $MYSQL ]; then
           echo "Installing MySQL client"
           sudo yum install libmysqlclient-dev mysql-server mysql-devel MySQL-python
        elif [ "$DBTYPE" == $POSTGRES ]; then
           echo "Installing Postgres client"
           sudo yum install libpq-dev postgresql postgresql-contrib libmysqlclient-dev
        fi
        sudo yum groupinstall 'Development Tools'
elif [[ ! -z "$APT_GET_CMD" ]]; then
     if [ "$DBTYPE" == $MYSQL ]; then
        echo "Installing MySQL client"
        sudo apt-get -y install libmysqlclient-dev mysql-server
     elif [ "$DBTYPE" == $POSTGRES ]; then
	echo "Installing Postgres client"
        sudo apt-get -y install libpq-dev postgresql postgresql-contrib libmysqlclient-dev
     fi

     sudo apt-get install -y libjpeg-dev gcc libssl-dev python-dev python-pip nodejs-legacy wkhtmltopdf npm
elif [[ ! -z "$BREW_CMD" ]]; then
    brew install gcc openssl python node npm Caskroom/cask/wkhtmltopdf
    if [ "$DBTYPE" == $MYSQL ]; then
        echo "Installing MySQL client"
        brew install mysql
    elif [ "$DBTYPE" == $POSTGRES ]; then
        echo "Installing Postgres client"
        brew install postgresql
    fi
else
	echo "ERROR! OS not supported. Try the Vagrant option."
	exit 1;
fi

# bower install
sudo npm install -g bower

echo

if [ "$DBTYPE" == $MYSQL ]; then
   echo "Installing MySQL client"
   get_db_details
elif [ "$DBTYPE" == $POSTGRES ]; then
   get_postgres_db_details
fi

unset HISTFILE

if [[ ! -z "$BREW_CMD" ]]; then
	LC_CTYPE=C
fi

SECRET=`cat /dev/urandom | LC_CTYPE=C tr -dc "a-zA-Z0-9" | head -c 128`

# Allow script to be called non-interactively using:
# export AUTO_DOCKER=yes && /opt/django-DefectDojo/setup.bash
if [ "$AUTO_DOCKER" != "yes" ]; then
    cp dojo/settings.dist.py dojo/settings.py
else
    # locate to the install directory first
    cd /opt/django-DefectDojo/
    cp dojo/settings.dist.py dojo/settings.py
fi

# Save MySQL details in settings file
if [[ ! -z $BREW_CMD ]]; then
  sed -i ''  "s/MYSQLHOST/$SQLHOST/g" dojo/settings.py
  sed -i ''  "s/MYSQLPORT/$SQLPORT/g" dojo/settings.py
  sed -i ''  "s/MYSQLUSER/$SQLUSER/g" dojo/settings.py
  sed -i ''  "s/MYSQLPWD/$SQLPWD/g" dojo/settings.py
  sed -i ''  "s/MYSQLDB/$DBNAME/g" dojo/settings.py
  sed -i ''  "s#DOJODIR#$PWD/dojo#g" dojo/settings.py
  sed -i ''  "s/DOJOSECRET/$SECRET/g" dojo/settings.py
  sed -i ''  "s#BOWERDIR#$PWD/components#g" dojo/settings.py
  sed -i ''  "s#DOJO_MEDIA_ROOT#$PWD/media/#g" dojo/settings.py
  sed -i ''  "s#DOJO_STATIC_ROOT#$PWD/static/#g" dojo/settings.py
  if [ "$DBTYPE" == '1' ]; then
    sed -i ''  "s/BACKENDDB/django.db.backends.mysql/g" dojo/settings.py
  elif [ "$DBTYPE" == '2' ]; then
    sed -i ''  "s/BACKENDDB/django.db.backends.postgresql_psycopg2/g" dojo/settings.py
  fi

else
  sed -i  "s/MYSQLHOST/$SQLHOST/g" dojo/settings.py
  sed -i  "s/MYSQLPORT/$SQLPORT/g" dojo/settings.py
  sed -i  "s/MYSQLUSER/$SQLUSER/g" dojo/settings.py
  sed -i  "s/MYSQLPWD/$SQLPWD/g" dojo/settings.py
  sed -i  "s/MYSQLDB/$DBNAME/g" dojo/settings.py
  sed -i  "s#DOJODIR#$PWD/dojo#g" dojo/settings.py
  sed -i  "s/DOJOSECRET/$SECRET/g" dojo/settings.py
  sed -i  "s#BOWERDIR#$PWD/components#g" dojo/settings.py
  sed -i  "s#DOJO_MEDIA_ROOT#$PWD/media/#g" dojo/settings.py
  sed -i  "s#DOJO_STATIC_ROOT#$PWD/static/#g" dojo/settings.py

  if [ "$DBTYPE" == '1' ]; then
    sed -i  "s/BACKENDDB/django.db.backends.mysql/g" dojo/settings.py
  elif [ "$DBTYPE" == '2' ]; then
    sed -i  "s/BACKENDDB/django.db.backends.postgresql_psycopg2/g" dojo/settings.py
  fi
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
    python manage.py makemigrations --merge --noinput
    python manage.py migrate
    echo -e "${GREEN}${BOLD}Create Dojo superuser:"
    tput sgr0
    python manage.py createsuperuser
    python manage.py loaddata product_type
    python manage.py loaddata test_type
    python manage.py loaddata development_environment
    python manage.py loaddata system_settings
    python manage.py installwatson
    python manage.py buildwatson
else
    pip install .
    python manage.py makemigrations dojo
    python manage.py makemigrations --merge --noinput
    python manage.py migrate
    # Allow script to be called non-interactively using:
    # export AUTO_DOCKER=yes && /opt/django-DefectDojo/setup.bash
    if [ "$AUTO_DOCKER" != "yes" ]; then
        echo -e "${GREEN}${BOLD}Create Dojo superuser:"
        tput sgr0
        python manage.py createsuperuser
    else
        # non-interactively setup the superuser
        python manage.py createsuperuser --noinput --username=admin --email='ed@example.com'
        /opt/django-DefectDojo/docker/setup-superuser.expect
    fi
    python manage.py loaddata product_type
    python manage.py loaddata test_type
    python manage.py loaddata development_environment
    python manage.py loaddata system_settings
    python manage.py installwatson
    python manage.py buildwatson
fi

if [ $(id -u) = 0 ]; then
    adduser --disabled-password --gecos "DefectDojo" dojo
    chown -R dojo:dojo /opt/django-DefectDojo
    su - dojo -c 'cd /opt/django-DefectDojo/components && bower install && cd ..'
else
    cd components && bower install && cd ..
fi

# Detect if we're in a a virtualenv
if python -c 'import sys; print sys.real_prefix' 2>/dev/null; then
    python manage.py collectstatic --noinput
else
    python manage.py collectstatic --noinput
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
