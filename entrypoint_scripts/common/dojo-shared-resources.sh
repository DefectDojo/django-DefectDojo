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
    echo ""
}

TARGET_DIR=
AUTO_DOCKER=

while getopts 'hry' opt; do
    case $opt in
        h)
            help
            exit 0
            ;;
        y)
            AUTO_DOCKER="yes"
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

# Supported databases
export SQLITE=0
export MYSQL=1
export POSTGRES=2

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
        DEFECT_DOJO_ADMIN_EMAIL='root@localhost.local'
    fi
    if [ -z "$DOJO_ADMIN_PASSWORD" ]; then
        DOJO_ADMIN_PASSWORD=`LC_CTYPE=C tr -dc A-Za-z0-9_\!\@\#\$\%\^\&\*\(\)-+ < /dev/urandom | head -c 32 | xargs`
    fi
    #creating default admin user
    echo "from django.contrib.auth.models import User; User.objects.create_superuser('$DOJO_ADMIN_USER', '$DOJO_ADMIN_EMAIL', '$DOJO_ADMIN_PASSWORD')" | ./manage.py shell
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
    virtualenv $DOJO_VENV_NAME
    source $DOJO_VENV_NAME/bin/activate

    verify_python_version

    echo "=============================================================================="
    echo "Pip install required components"
    echo "=============================================================================="
    echo
    pip install .

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
        echo "Please enter 1 or 2"
        prompt_db_type
    fi
}

# Ensures the mysql application DB is present
function ensure_mysql_application_db() {
    # Allow script to be called non-interactively using:
    # export AUTO_DOCKER=yes && /opt/django-DefectDojo/setup.bash
    if [ "$AUTO_DOCKER" != "yes" ]; then
        # Run interactively
        read -p "MySQL host: " DEFECT_DOJO_DEFAULT_DATABASE_HOST
        read -p "MySQL port: " DEFECT_DOJO_DEFAULT_DATABASE_PORT
        read -p "MySQL user (should already exist): " DEFECT_DOJO_DEFAULT_DATABASE_USER
        stty -echo
        read -p "Password for user: " DEFECT_DOJO_DEFAULT_DATABASE_PASSWORD; echo
        stty echo
        read -p "Database name (should NOT exist): " DEFECT_DOJO_DEFAULT_DATABASE_NAME
    fi

    if mysql -fs --protocol=TCP -h "$DEFECT_DOJO_DEFAULT_DATABASE_HOST" -P "$DEFECT_DOJO_DEFAULT_DATABASE_PORT" -u"$DEFECT_DOJO_DEFAULT_DATABASE_USER" -p"$DEFECT_DOJO_DEFAULT_DATABASE_PASSWORD" "$DEFECT_DOJO_DEFAULT_DATABASE_NAME" >/dev/null 2>&1 </dev/null; then
        echo "Database $DEFECT_DOJO_DEFAULT_DATABASE_NAME already exists!"
        echo
        if [ "$AUTO_DOCKER" == "yes" ]; then
            if [ -z "$FLUSHDB" ]; then
                DELETE="yes"
            else
                DELETE="$FLUSHDB"
            fi
        else
            read -p "Drop database $DEFECT_DOJO_DEFAULT_DATABASE_NAME? [Y/n] " DELETE
        fi
        if [[ ! $DELETE =~ ^[nN]$ ]]; then
            mysqladmin -f --protocol=TCP --host="$DEFECT_DOJO_DEFAULT_DATABASE_HOST" --port="$DEFECT_DOJO_DEFAULT_DATABASE_PORT" --user="$DEFECT_DOJO_DEFAULT_DATABASE_USER" --password="$DEFECT_DOJO_DEFAULT_DATABASE_PASSWORD" drop "$DEFECT_DOJO_DEFAULT_DATABASE_NAME"
            mysqladmin    --protocol=TCP --host="$DEFECT_DOJO_DEFAULT_DATABASE_HOST" --port="$DEFECT_DOJO_DEFAULT_DATABASE_PORT" --user="$DEFECT_DOJO_DEFAULT_DATABASE_USER" --password="$DEFECT_DOJO_DEFAULT_DATABASE_PASSWORD" create "$DEFECT_DOJO_DEFAULT_DATABASE_NAME"
        fi
    else
        # Set the root password for mysql - install has it blank
        mysql -uroot -e "SET PASSWORD = PASSWORD('${DEFECT_DOJO_DEFAULT_DATABASE_PASSWORD}');"

        if mysqladmin --protocol=TCP --host="$DEFECT_DOJO_DEFAULT_DATABASE_HOST" --port="$DEFECT_DOJO_DEFAULT_DATABASE_PORT" --user="$DEFECT_DOJO_DEFAULT_DATABASE_USER" --password="$DEFECT_DOJO_DEFAULT_DATABASE_PASSWORD" create $DEFECT_DOJO_DEFAULT_DATABASE_NAME; then
            echo "Created database $DEFECT_DOJO_DEFAULT_DATABASE_NAME."
        else
            echo "Error! Failed to create database $DEFECT_DOJO_DEFAULT_DATABASE_NAME. Check your credentials."
            echo
            ensure_mysql_application_db
        fi
    fi
}

# Ensures the Postgres application DB is present
function ensure_postgres_application_db() {
    read -p "Postgres host: " DEFECT_DOJO_DEFAULT_DATABASE_HOST
    read -p "Postgres port: " DEFECT_DOJO_DEFAULT_DATABASE_PORT
    read -p "Postgres user (should already exist): " DEFECT_DOJO_DEFAULT_DATABASE_USER
    stty -echo
    read -p "Password for user: " DEFECT_DOJO_DEFAULT_DATABASE_PASSWORD; echo
    stty echo
    read -p "Database name (should NOT exist): " DEFECT_DOJO_DEFAULT_DATABASE_NAME

    if [ "$( PGPASSWORD=$DEFECT_DOJO_DEFAULT_DATABASE_PASSWORD psql -h $DEFECT_DOJO_DEFAULT_DATABASE_HOST -p $DEFECT_DOJO_DEFAULT_DATABASE_PORT -U $DEFECT_DOJO_DEFAULT_DATABASE_USER -tAc "SELECT 1 FROM pg_database WHERE datname='$DEFECT_DOJO_DEFAULT_DATABASE_NAME'" )" = '1' ]
    then
        echo "Database $DEFECT_DOJO_DEFAULT_DATABASE_NAME already exists!"
        echo
        read -p "Drop database $DEFECT_DOJO_DEFAULT_DATABASE_NAME? [Y/n] " DELETE
        if [[ ! $DELETE =~ ^[nN]$ ]]; then
            PGPASSWORD=$DEFECT_DOJO_DEFAULT_DATABASE_PASSWORD dropdb $DEFECT_DOJO_DEFAULT_DATABASE_NAME -h $DEFECT_DOJO_DEFAULT_DATABASE_HOST -p $DEFECT_DOJO_DEFAULT_DATABASE_PORT -U $DEFECT_DOJO_DEFAULT_DATABASE_USER
            PGPASSWORD=$DEFECT_DOJO_DEFAULT_DATABASE_PASSWORD createdb $DEFECT_DOJO_DEFAULT_DATABASE_NAME -h $DEFECT_DOJO_DEFAULT_DATABASE_HOST -p $DEFECT_DOJO_DEFAULT_DATABASE_PORT -U $DEFECT_DOJO_DEFAULT_DATABASE_USER
        else
            read -p "Try and install anyway? [Y/n] " INSTALL
            if [[ $INSTALL =~ ^[nN]$ ]]; then
              echo
              ensure_postgres_application_db
            fi
        fi
    else
        PGPASSWORD=$DEFECT_DOJO_DEFAULT_DATABASE_PASSWORD createdb $DEFECT_DOJO_DEFAULT_DATABASE_NAME -h $DEFECT_DOJO_DEFAULT_DATABASE_HOST -p $DEFECT_DOJO_DEFAULT_DATABASE_PORT -U $DEFECT_DOJO_DEFAULT_DATABASE_USER
        if [ $? = 0 ]
        then
            echo "Created database $DEFECT_DOJO_DEFAULT_DATABASE_NAME."
        else
            echo "Error! Failed to create database $DEFECT_DOJO_DEFAULT_DATABASE_NAME. Check your credentials."
            echo
            ensure_postgres_application_db
        fi
    fi
}

function ensure_application_db() {
    # Setup the application DB
    echo "Ensure application DB is present"
    if [ "$DBTYPE" == $MYSQL ]; then
        ensure_mysql_application_db
    elif [ "$DBTYPE" == $POSTGRES ]; then
        ensure_postgres_application_db
    fi
}

# Set up packages via Yum / APT
function install_os_dependencies() {
    YUM_CMD=$(which yum)
    APT_GET_CMD=$(which apt-get)
    BREW_CMD=$(which brew)

    if [[ ! -z "$YUM_CMD" ]]; then
        sudo yum install wget epel-release
        curl -sL https://rpm.nodesource.com/setup | sudo bash -
        sudo wget https://dl.yarnpkg.com/rpm/yarn.repo -O /etc/yum.repos.d/yarn.repo
        sudo yum install gcc python-devel python-setuptools python-pip nodejs yarn wkhtmltopdf
        sudo yum groupinstall 'Development Tools'
    elif [[ ! -z "$APT_GET_CMD" ]]; then
        sudo apt-get install -y curl apt-transport-https
        #Yarn
        curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
        echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
        #Node
        curl -sL https://deb.nodesource.com/setup_6.x | sudo -E bash
        sudo apt-get update && sudo apt-get install -y apt-transport-https libjpeg-dev gcc libssl-dev python-dev python-pip nodejs yarn wkhtmltopdf build-essential
    elif [[ ! -z "$BREW_CMD" ]]; then
        brew install gcc openssl python node npm yarn Caskroom/cask/wkhtmltopdf
    else
        echo "ERROR! OS not supported. Try the Vagrant option."
        exit 1;
    fi

    echo
}

function install_db() {
    YUM_CMD=$(which yum)
    APT_GET_CMD=$(which apt-get)
    BREW_CMD=$(which brew)

    if [[ ! -z "$YUM_CMD" ]]; then
        if [ "$DBTYPE" == $MYSQL ]; then
            echo "Installing MySQL client (and server if not already installed)"
            sudo yum install mariadb-server mysql-devel
        elif [ "$DBTYPE" == $POSTGRES ]; then
            echo "Installing Postgres client (and server if not already installed)"
            sudo yum install postgresql-devel postgresql postgresql-contrib
        fi
    elif [[ ! -z "$APT_GET_CMD" ]]; then
        if [ "$DBTYPE" == $MYSQL ]; then
            echo "Installing MySQL client (and server if not already installed)"
            sudo apt-get install -y libmysqlclient-dev mysql-server
        elif [ "$DBTYPE" == $POSTGRES ]; then
            echo "Installing Postgres client (and server if not already installed)"
            sudo apt-get install -y libpq-dev postgresql postgresql-contrib libmysqlclient-dev
        fi
    elif [[ ! -z "$BREW_CMD" ]]; then
        if [ "$DBTYPE" == $MYSQL ]; then
            echo "Installing MySQL client"
            brew install mysql
        elif [ "$DBTYPE" == $POSTGRES ]; then
            echo "Installing Postgres client"
            brew install postgresql
        fi
    fi
}

function prepare_settings_file() {
    unset HISTFILE

    if [[ ! -z "$BREW_CMD" ]]; then
        LC_CTYPE=C
    fi

    SECRET=`cat /dev/urandom | LC_CTYPE=C tr -dc "a-zA-Z0-9" | head -c 128`
}

function install_app() {
    # Install the app, apply migrations and load data

    # Detect if we're in a a virtualenv
    python -c 'import sys; print sys.real_prefix' 2>/dev/null
    VENV_ACTIVE=$?

    if [ "$VENV_ACTIVE" == "0" ]; then
        pip install -U pip
        if [ "$DBTYPE" == "$MYSQL" ]; then
            pip install .[mysql]
        else
            pip install .
        fi
    else
        if [ "$DBTYPE" == "$MYSQL" ]; then
            sudo -H pip install .[mysql]
        else
            sudo -H pip install .
        fi
    fi
    python manage.py makemigrations dojo
    python manage.py makemigrations --merge --noinput
    python manage.py migrate

    if [ "$VENV_ACTIVE" == "0" ]; then
        # If a virtualenv is active...
        echo -e "${GREEN}${BOLD}Create Dojo superuser:"
        tput sgr0
        python manage.py createsuperuser
    else
        # Allow script to be called non-interactively using:
        # export AUTO_DOCKER=yes && /opt/django-DefectDojo/setup.bash
        if [ "$AUTO_DOCKER" != "yes" ]; then
            echo -e "${GREEN}${BOLD}Create Dojo superuser:"
            tput sgr0
            python manage.py createsuperuser
        else
            # non-interactively setup the superuser
            python manage.py createsuperuser --noinput --username=admin --email='ed@example.com'
            docker/setup-superuser.expect
        fi
    fi

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
}
