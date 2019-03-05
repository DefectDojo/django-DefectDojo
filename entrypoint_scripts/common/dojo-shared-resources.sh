#!/usr/bin/env bash
###############################################################################
#####
##### Shared set of variables and functions for setting up dojo
#####
###############################################################################

function help() {
    echo ""
    echo "$0 usage:"
    echo "  -h      Display this help message and exit with a status code of 0"
    echo "  -y      Disable interactivity (i.e. useful for Dockerfile usage)"
    echo "  -b      Batch mode (i.e useful for automation purpose)"
    echo ""
}

TARGET_DIR=
AUTO_DOCKER=

# Supported databases
export SQLITE=0
export MYSQL=1
export POSTGRES=2

while getopts 'hr:y:b:d:' opt; do
    case $opt in
        h)
            help
            exit 0
            ;;
        y)
            AUTO_DOCKER="yes"
            FUNCTION=$OPTARG
            ;;
        d)
            if [[ "$OPTARG" == "MYSQL" ]]; then
                DBTYPE=$MYSQL
            elif [[ "$OPTARG" == "POSTGRES" ]]; then
                DBTYPE=$POSTGRES
            else
                DBTYPE=$SQLITE
            fi
            ;;
        b)
            BATCH_MODE="yes"
            ;;
        ?)
            help
            exit 1
            ;;
    esac
done

# Set up output text styles
export NONE='\033[00m'
export RED='\033[01;31m'
export GREEN='\033[01;32m'
export YELLOW='\033[01;33m'
export PURPLE='\033[01;35m'
export CYAN='\033[01;36m'
export WHITE='\033[01;37m'
export BOLD='\033[1m'
export UNDERLINE='\033[4m'

# Main DefectDojo directory
export DOJO_ROOT_DIR=$PWD
# The name of the virtualenv
export DOJO_VENV_NAME=venv

function verify_cwd() {
    required_fs_objects="manage.py setup.bash dojo"
    for obj in $required_fs_objects; do
        if [ ! -e $obj ]; then
            echo "Couldn't find '$obj' in $DOJO_ROOT_DIR; Please run this script at the application's root directory" >&2
            exit 1
        fi
    done
}

###
### Declare functions required and used throughout scripts
###
function createadmin() {
    echo "=============================================================================="
    echo "Creating Dojo Admin User"
    echo "=============================================================================="
    echo

    #setup default admin dojo user
    if [ -z "$DEFECT_DOJO_ADMIN_NAME" ]; then
        DEFECT_DOJO_ADMIN_NAME='admin'
    fi
    if [ -z "$DEFECT_DOJO_ADMIN_EMAIL" ]; then
        DEFECT_DOJO_ADMIN_EMAIL='admin@localhost.local'
    fi
    if [ -z "$DD_ADMIN_PASSWORD" ]; then
        DD_ADMIN_PASSWORD="admin"
    fi
    export DD_ADMIN_PASSWORD=$DD_ADMIN_PASSWORD
    #creating default admin user
    python manage.py createsuperuser --noinput --username="$DEFECT_DOJO_ADMIN_NAME" --email="$DEFECT_DOJO_ADMIN_EMAIL"
    docker/setup-superuser.expect
}

function setupdb() {
    echo "=============================================================================="
    echo "Setting up dojodb"
    echo "=============================================================================="
    echo
    python manage.py makemigrations dojo
    python manage.py makemigrations --merge --noinput
    python manage.py migrate
    python manage.py syncdb --noinput
    python manage.py loaddata product_type
    python manage.py loaddata test_type
    python manage.py loaddata development_environment
    python manage.py loaddata system_settings
    python manage.py installwatson
    python manage.py buildwatson

    echo "=============================================================================="
    echo "Collect Static Files"
    echo "=============================================================================="
    echo
    #Collect static files
    python manage.py collectstatic --noinput

    echo "=============================================================================="
    echo "Checking if sample data should be loaded"
    echo "=============================================================================="
    echo
    if [ "$LOAD_SAMPLE_DATA" = True ]; then
        echo
        echo "Loading sample data..."
        bash $DOCKER_DIR/dojo-data.bash load
        echo
    fi
}

function verify_python_version() {
    # Detect Python version
    PYV=`python -c "import sys;t='{v[0]}.{v[1]}'.format(v=list(sys.version_info[:2]));sys.stdout.write(t)";`
    if [[ "$PYV"<"2.7" ]]; then
        echo "ERROR: DefectDojo requires Python 2.7+"
        exit 1;
    else
        echo "Leaving Django 1.x.y requirement"
    fi
}

function setupdojo() {
    echo "=============================================================================="
    echo "DefectDojo Setup"
    echo "Installing required packages"
    echo "=============================================================================="
    echo

    echo "=============================================================================="
    echo "Installing Yarn"
    echo "=============================================================================="
    echo
    # yarn install
    npm install -g yarn

    echo "=============================================================================="
    echo "Creating Virtual Environment"
    echo "=============================================================================="
    echo
    #Remove any previous virtual environments
    if [ -d $DOJO_VENV_NAME ];
    then
        rm -r $DOJO_VENV_NAME
    fi
    pip install virtualenv
    virtualenv $DOJO_VENV_NAME
    source $DOJO_VENV_NAME/bin/activate

    verify_python_version

    echo "=============================================================================="
    echo "Pip install required components"
    echo "=============================================================================="
    echo
    pip install . --ignore-installed Markdown

    echo "=============================================================================="
    echo "Installing yarn"
    echo "=============================================================================="
    echo
    cd components && yarn && cd ..

    # Setup the DB
    setupdb

    echo "=============================================================================="
    echo "SUCCESS!"
    echo "=============================================================================="
}

function prompt_db_type() {
    read -p "Select database type: 0.) SQLite, 1.) MySQL or 2.) Postgres: " DBTYPE
    if [ "$DBTYPE" == "$SQLITE" ] \
        || [ "$DBTYPE" == "$MYSQL" ] \
        || [ "$DBTYPE" == "$POSTGRES" ] ; then
    	echo "Setting up database"
    else
        echo "Please enter 0, 1 or 2"
        prompt_db_type
    fi
}

# Ensures the mysql application DB is present
function ensure_mysql_application_db() {
    # Allow script to be called non-interactively using:
    if [ "$AUTO_DOCKER" == "yes" ]; then
        echo "Setting values for MySQL install"
        if [ -z "$DD_DATABASE_HOST" ]; then
            DD_DATABASE_HOST="localhost"
        fi
        if [ -z "$DD_DATABASE_PORT" ]; then
            DD_DATABASE_PORT="3306"
        fi
        if [ -z "$DD_DATABASE_USER" ]; then
            DD_DATABASE_USER="root"
        fi
        if [ -z "$DD_DATABASE_PASsWORD" -a "$BATCH_MODE" == "yes" ]; then
            echo "SQL Password not provided, exiting"
            exit 1
        else
            DD_DATABASE_PASsWORD="dojodb_install"
        fi
        if [ -z "$DD_DATABASE_NAME" ]; then
            DD_DATABASE_NAME="dojodb"
        fi
    fi

    if mysql -fs --protocol=TCP -h "$DD_DATABASE_HOST" -P "$DD_DATABASE_PORT" -u"$DD_DATABASE_USER" -p"$DD_DATABASE_PASsWORD" "$DD_DATABASE_NAME" >/dev/null 2>&1 </dev/null; then
        echo "Database $DD_DATABASE_NAME already exists!"
        echo
        if [ "$AUTO_DOCKER" == "yes" ] || [ "$BATCH_MODE" == "yes" ]; then
            if [ -z "$FLUSHDB" ]; then
                DELETE="yes"
            else
                DELETE="$FLUSHDB"
            fi
        else
            read -p "Drop database $DD_DATABASE_NAME? [Y/n] " DELETE
        fi
        if [[ ! $DELETE =~ ^[nN]$ ]]; then
            mysqladmin -f --protocol=TCP --host="$DD_DATABASE_HOST" --port="$DD_DATABASE_PORT" --user="$DD_DATABASE_USER" --password="$DD_DATABASE_PASsWORD" drop "$DD_DATABASE_NAME"
            mysqladmin    --protocol=TCP --host="$DD_DATABASE_HOST" --port="$DD_DATABASE_PORT" --user="$DD_DATABASE_USER" --password="$DD_DATABASE_PASsWORD" create "$DD_DATABASE_NAME"
        fi
    else
        echo "Setting password..."
        # Set the root password for mysql
        set_random_mysql_db_pwd
        sudo service mysql start
        if mysqladmin --protocol=TCP --host="$DD_DATABASE_HOST" --port="$DD_DATABASE_PORT" --user="$DD_DATABASE_USER" --password="$DD_DATABASE_PASsWORD" create $DD_DATABASE_NAME; then
            echo "Created database $DD_DATABASE_NAME."
        else
            echo "Error! Failed to create database $DD_DATABASE_NAME. Check your credentials."
            echo
            ensure_mysql_application_db
        fi
    fi
}

# Ensures the Postgres application DB is present
function ensure_postgres_application_db() {
    read -p "Postgres host: " $DD_DATABASE_HOST
    read -p "Postgres port: " $DD_DATABASE_PORT
    read -p "Postgres user (should already exist): " $DD_DATABASE_USER
    stty -echo
    read -p "Password for user: " $DD_DATABASE_PASsWORD; echo
    stty echo
    read -p "Database name (should NOT exist): " $DD_DATABASE_NAME

    if [ "$( PGPASSWORD=$DD_DATABASE_PASsWORD psql -h $DD_DATABASE_HOST -p $DD_DATABASE_PORT -U $DD_DATABASE_USER -tAc "SELECT 1 FROM pg_database WHERE datname='$DD_DATABASE_NAME'" )" = '1' ]
    then
        echo "Database $DD_DATABASE_NAME already exists!"
        echo
        read -p "Drop database $DD_DATABASE_NAME? [Y/n] " DELETE
        if [[ ! $DELETE =~ ^[nN]$ ]]; then
            PGPASSWORD=$DD_DATABASE_PASsWORD dropdb $DD_DATABASE_NAME -h $DD_DATABASE_HOST -p $DD_DATABASE_PORT -U $DD_DATABASE_USER
            PGPASSWORD=$DD_DATABASE_PASsWORD createdb $DD_DATABASE_NAME -h $DD_DATABASE_HOST -p $DD_DATABASE_PORT -U $DD_DATABASE_USER
        else
            read -p "Try and install anyway? [Y/n] " INSTALL
            if [[ $INSTALL =~ ^[nN]$ ]]; then
              echo
              ensure_postgres_application_db
            fi
        fi
    else
        PGPASSWORD=$DD_DATABASE_PASsWORD createdb $DD_DATABASE_NAME -h $DD_DATABASE_HOST -p $DD_DATABASE_PORT -U $DD_DATABASE_USER
        if [ $? = 0 ]
        then
            echo "Created database $DD_DATABASE_NAME."
        else
            echo "Error! Failed to create database $DD_DATABASE_NAME. Check your credentials."
            echo
            ensure_postgres_application_db
        fi
    fi
}

function ensure_application_db() {
    # Setup the application DB
    echo "Ensure application DB is present"
    if [ "$DBTYPE" == "$MYSQL" ]; then
        ensure_mysql_application_db
    elif [ "$DBTYPE" == "$POSTGRES" ]; then
        ensure_postgres_application_db
    fi
}

# Set up packages via Yum / APT
function install_os_dependencies() {
    echo "Installing OS Dependencies"
    YUM_CMD=$(which yum)
    APT_GET_CMD=$(which apt-get)
    BREW_CMD=$(which brew)

    if [[ ! -z "$YUM_CMD" ]]; then
        sudo yum install -y wget epel-release
        curl -sL https://rpm.nodesource.com/setup | sudo bash -
        sudo wget https://dl.yarnpkg.com/rpm/yarn.repo -O /etc/yum.repos.d/yarn.repo
        sudo yum install gcc python-devel python-setuptools python-pip nodejs yarn wkhtmltopdf expect
        sudo yum groupinstall 'Development Tools'
    elif [[ ! -z "$APT_GET_CMD" ]]; then
        if [ "$AUTO_DOCKER" == "yes" ]; then
          echo "Installing Docker OS Dependencies"
          DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y sudo git nano
        fi
        sudo DEBIAN_FRONTEND=noninteractive apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y curl apt-transport-https expect gnupg2
        #Node
        curl -sL https://deb.nodesource.com/setup_6.x | sudo -E bash
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y apt-transport-https libjpeg-dev gcc libssl-dev python-dev python-pip nodejs wkhtmltopdf build-essential

        #Yarn from cmdtest conflicts
        sudo apt -y remove cmdtest
        curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
        echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
        sudo DEBIAN_FRONTEND=noninteractive apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y yarn

    elif [[ ! -z "$BREW_CMD" ]]; then
        brew install gcc openssl python node npm yarn Caskroom/cask/wkhtmltopdf expect
    else
        echo "ERROR! OS not supported, please try Docker. https://hub.docker.com/r/appsecpipeline/django-defectdojo/"
        exit 1;
    fi

    echo
}

function urlenc() {
	local STRING="${1}"
	echo `python -c "import sys, urllib as ul; print ul.quote_plus('$STRING')"`
}

function install_db() {
    YUM_CMD=$(which yum)
    APT_GET_CMD=$(which apt-get)
    BREW_CMD=$(which brew)

    if [[ ! -z "$YUM_CMD" ]]; then
        if [ "$DBTYPE" == $MYSQL ]; then
            echo "Installing MySQL client (and server if not already installed)"
            sudo yum install -y mariadb-server mysql-devel
        elif [ "$DBTYPE" == $POSTGRES ]; then
            echo "Installing Postgres client (and server if not already installed)"
            sudo yum install -y postgresql-devel postgresql postgresql-contrib
        fi
    elif [[ ! -z "$APT_GET_CMD" ]]; then
        if [ "$DBTYPE" == $MYSQL ]; then
            echo "Installing MySQL client (and server if not already installed)"
            if [ "$AUTO_DOCKER" == "yes" ]; then
              DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server pwgen libmysqlclient-dev
              echo "MySQL client (and server if not already installed) setup complete"
              sudo service mysql start
            else
              sudo apt-get install -y libmysqlclient-dev mysql-server
            fi
        elif [ "$DBTYPE" == $POSTGRES ]; then
            echo "Installing Postgres client (and server if not already installed)"
            sudo apt-get install -y libpq-dev postgresql postgresql-contrib
        fi
    elif [[ ! -z "$BREW_CMD" ]]; then
        if [ "$DBTYPE" == $MYSQL ]; then
            echo "Installing MySQL client"
            brew install mysql@5.7
	    brew link mysql@5.7 --force
        elif [ "$DBTYPE" == $POSTGRES ]; then
            echo "Installing Postgres client"
            brew install postgresql
        fi
    fi
}

function setup_batch_mode() {
  # Batch mode
  echo "Installing DefectDojo in batch mode."
  if [[ -z "$DD_ENV_PATH" ]]; then
    echo "Please set the env file to use. (DD_ENV)"
  fi
  source "dojo/settings/$DD_ENV_PATH"
  PARSE_DB_URL="$(python entrypoint_scripts/misc/url_db.py $DD_DATABASE_URL)"
  echo
  IFS=":"
  read DBTYPE DBNAME SQLUSER SQLPWD SQLHOST SQLPORT<<<"$PARSE_DB_URL"
  if [ $DBTYPE=="mysql" ]; then
    DBTYPE=$MYSQL
  elif [ $DBTYPE=="postgres" ]; then
    DBTYPE=$POSTGRES
  else
    DBTYPE=$SQLITE
  fi
}

function prepare_settings_file() {
    echo "=============================================================================="
    echo "Creating dojo/settings/settings.py and .env file"
    echo "=============================================================================="
    echo
    unset HISTFILE

    if [[ ! -z "$BREW_CMD" ]]; then
        LC_CTYPE=C
    fi

    SECRET=`cat /dev/urandom | LC_CTYPE=C tr -dc "a-zA-Z0-9" | head -c 128`
    AES_PASSPHRASE=`cat /dev/urandom | LC_CTYPE=C tr -dc "a-zA-Z0-9" | head -c 128`
    TARGET_SETTINGS_FILE=dojo/settings/settings.py
    ENV_SETTINGS_FILE=dojo/settings/.env.prod

    # Copy settings file
    sudo cp dojo/settings/settings.dist.py ${TARGET_SETTINGS_FILE}

    # Remove existing .env.prod files
    if [ ${ENV_SETTINGS_FILE} ]; then
      sudo rm ${ENV_SETTINGS_FILE}
    fi

    # Create the env file
    touch ${ENV_SETTINGS_FILE}

    # DD_DATABASE_URL can be set as an environment variable, if not construct
    if [ "$DBTYPE" == "$SQLITE" ]; then
        echo 'DD_DATABASE_URL="sqlite:///defectdojo.db"' >> ${ENV_SETTINGS_FILE}
    elif [ "$DBTYPE" == "$MYSQL" ]; then
        SAFE_URL=$(urlenc "$DD_DATABASE_USER")":"$(urlenc "$DD_DATABASE_PASsWORD")"@"$(urlenc "$DD_DATABASE_HOST")":"$(urlenc "$DD_DATABASE_PORT")"/"$(urlenc "$DD_DATABASE_NAME")
        echo "DD_DATABASE_URL=mysql://$SAFE_URL" >> ${ENV_SETTINGS_FILE}
    elif [ "$DBTYPE" == "$POSTGRES" ]; then
        SAFE_URL=$(urlenc "$DD_DATABASE_USER")":"$(urlenc "$DD_DATABASE_PASsWORD")"@"$(urlenc "$DD_DATABASE_HOST")":"$(urlenc "$DD_DATABASE_PORT")"/"$(urlenc "$DD_DATABASE_NAME")
        echo "DD_DATABASE_URL=postgres://$SAFE_URL" >> ${ENV_SETTINGS_FILE}
    fi

    if [[ $DD_ALLOWED_HOSTS ]]; then
        echo 'DD_ALLOWED_HOSTS="localhost"' >> ${ENV_SETTINGS_FILE}
    fi

    echo 'DD_DEBUG="on"' >> ${ENV_SETTINGS_FILE}
    echo 'DD_SECRET_KEY="'${SECRET}'"' >> ${ENV_SETTINGS_FILE}
    echo 'DD_CREDENTIAL_AES_256_KEY="'${AES_PASSPHRASE}'"' >> ${ENV_SETTINGS_FILE}
}

function install_app() {
    # Install the app, apply migrations and load data
    # Detect if we're in a a virtualenv
    python -c 'import sys; print sys.real_prefix' 2>/dev/null
    VENV_ACTIVE=$?

    if [ "$VENV_ACTIVE" == "0" ]; then
        pip install --upgrade pip
        pip install -U pip
        if [ "$DBTYPE" == "$MYSQL" ]; then
            pip install .[mysql] --ignore-installed Markdown
        else
            pip install . --ignore-installed Markdown
        fi
    else
        sudo pip install --upgrade pip
        if [ "$DBTYPE" == "$MYSQL" ]; then
            sudo -H pip install .[mysql] --ignore-installed Markdown
        else
            sudo -H pip install . --ignore-installed Markdown
        fi
    fi
    python manage.py makemigrations dojo
    python manage.py makemigrations --merge --noinput
    python manage.py migrate

    if [ "$AUTO_DOCKER" == "yes" ]; then
      createadmin
    elif [ -z "$AUTO_DOCKER" ]; then
      echo -e "${GREEN}${BOLD}Create Dojo superuser:"
      tput sgr0
      python manage.py createsuperuser
    fi

    if [ "$AUTO_DOCKER" == "yes" ]; then
      python manage.py loaddata dojo/fixtures/defect_dojo_sample_data.json
    else
      python manage.py loaddata product_type
      python manage.py loaddata test_type
      python manage.py loaddata development_environment
      python manage.py loaddata system_settings
      python manage.py loaddata benchmark_type
      python manage.py loaddata benchmark_category
      python manage.py loaddata benchmark_requirement
      python manage.py loaddata language_type
      python manage.py loaddata objects_review
      python manage.py loaddata regulation
    fi

    python manage.py installwatson
    python manage.py buildwatson

    # Install yarn packages
    cd components && yarn && cd ..

    python manage.py collectstatic --noinput
}

function start_local_mysql_db_server() {
    # Nasty workaround according to https://serverfault.com/a/872576
    # This error was observed only on travis and not locally:
    # "Fatal error: Can't open and lock privilege tables: Table storage engine for 'user' doesn't have this option"
    sudo chown -R mysql:mysql /var/lib/mysql /var/run/mysqld
    sudo service mysql start
}

function stop_local_mysql_db_server() {
    sudo service mysql stop
    sudo chown -R mysql:mysql /var/lib/mysql /var/run/mysqld
}

function set_random_mysql_db_pwd() {
  sudo chown -R mysql:mysql /var/lib/mysql /var/run/mysqld
  sudo mysqld_safe --skip-grant-tables >/dev/null 2>&1 &
  sleep 5
  DB_ROOT_PASS_LEN=`shuf -i 50-60 -n 1`
  if [[ -z "$DD_DATABASE_PASsWORD" ]]; then
    DD_DATABASE_PASsWORD=`pwgen -scn $DB_ROOT_PASS_LEN 1`
  fi
  mysql mysql -e "UPDATE user SET authentication_string=PASSWORD('$DD_DATABASE_PASsWORD'), plugin='mysql_native_password' WHERE User='root';FLUSH PRIVILEGES;"
  sudo service mysql stop
}

function upgrade() {
  apt-get -y upgrade
  apt-get clean all
}

function remove_install_artifacts() {
  # sudo deluser dojo sudo
  # nodejs yarn autoremove
  sudo apt-get remove -y mysql-server
}

function install_postgres_client() {
  sudo apt-get install -y postgresql-client
  sudo apt-get upgrade
  sudo apt-get clean all
}

function slim_defect_dojo_settings() {
  # Copy settings file
  ENV_SETTINGS_FILE=dojo/settings/.env.prod
  rm ${ENV_SETTINGS_FILE}
}
