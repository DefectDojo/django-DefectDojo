#!/usr/bin/env bash
#####################################################################################
#####
##### Shared set of functions for setting up dojo
#####
#####################################################################################

function verify_cwd() {
    current_folder_name=$(basename $PWD)
    if [ "$current_folder_name" != "$DOJO_APP_DIR_NAME" ]; then
        echo "The current working dir is NOT the app's root directory"
        return 1
    fi
    return 0
}

function createadmin() {
    echo "=============================================================================="
    echo "Creating Dojo Admin User"
    echo "=============================================================================="
    echo

    #setup default admin dojo user
    if [ -z "$DOJO_ADMIN_USER" ]; then
        DOJO_ADMIN_USER='admin'
    fi
    if [ -z "$DOJO_ADMIN_EMAIL" ]; then
        DOJO_ADMIN_EMAIL='admin@localhost.local'
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
    #Create virtual environment
    cd $DOJO_ROOT_DIR
    #Remove any previous virtual environments
    if [ -d venv ];
    then
        rm -r venv
    fi
    virtualenv venv
    source venv/bin/activate

    verify_python_version

    echo "=============================================================================="
    echo "Pip install required components"
    echo "=============================================================================="
    echo
    pip install .

    echo "=============================================================================="
    echo "Copying settings.py"
    echo "=============================================================================="
    echo
    #Copying setting.py temporarily so that collect static will run correctly
    cp $DOJO_ROOT_DIR/dojo/settings/settings.dist.py $DOJO_ROOT_DIR/dojo/settings/settings.py
    sed -i "s#DOJO_STATIC_ROOT#$PWD/static/#g" $DOJO_ROOT_DIR/dojo/settings/settings.py

    echo "Setting dojo settings for SQLLITEDB."
    SQLLITEDB="'NAME': os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'db.sqlite3')"
    sed -i "s/django.db.backends.mysql/django.db.backends.sqlite3/g" dojo/settings/settings.py
    sed -i "s/'NAME': 'MYSQLDB'/$SQLLITEDB/g" dojo/settings/settings.py

    echo "=============================================================================="
    echo "Installing yarn"
    echo "=============================================================================="
    echo
    cd $DOJO_ROOT_DIR/components && yarn && cd ..

    # Setup the DB
    setupdb

    echo "=============================================================================="
    echo "Removing temporary files"
    echo "=============================================================================="
    echo
    rm $DOJO_ROOT_DIR/dojo/settings/settings.dist.py

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

    if mysql -fs --protocol=TCP -h "$SQLHOST" -P "$SQLPORT" -u"$SQLUSER" -p"$SQLPWD" "$DBNAME" >/dev/null 2>&1 </dev/null; then
        echo "Database $DBNAME already exists!"
        echo
        read -p "Drop database $DBNAME? [Y/n] " DELETE
        if [[ ! $DELETE =~ ^[nN]$ ]]; then
            mysqladmin -f --protocol=TCP --host="$SQLHOST" --port="$SQLPORT" --user="$SQLUSER" --password="$SQLPWD" drop "$DBNAME"
            mysqladmin    --protocol=TCP --host="$SQLHOST" --port="$SQLPORT" --user="$SQLUSER" --password="$SQLPWD" create "$DBNAME"
        else
            echo "Error! Must supply an empty database to proceed."
            echo
            ensure_mysql_application_db
        fi
    else
        if mysqladmin --protocol=TCP --host="$SQLHOST" --port="$SQLPORT" --user="$SQLUSER" --password="$SQLPWD" create $DBNAME; then
            echo "Created database $DBNAME."
        else
            echo "Error! Failed to create database $DBNAME. Check your credentials."
            echo
            ensure_mysql_application_db
        fi
    fi
}

# Ensures the Postgres application DB is present
function ensure_postgres_application_db() {
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
              ensure_postgres_application_db
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
        curl -sL https://rpm.nodesource.com/setup | sudo bash -
        wget https://dl.yarnpkg.com/rpm/yarn.repo -O /etc/yum.repos.d/yarn.repo
        sudo yum install gcc python-devel python-setuptools python-pip nodejs yarn wkhtmltopdf npm
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
            sudo yum install libmysqlclient-dev mysql-server mysql-devel
        elif [ "$DBTYPE" == $POSTGRES ]; then
            echo "Installing Postgres client (and server if not already installed)"
            sudo yum install libpq-dev postgresql postgresql-contrib libmysqlclient-dev
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
    echo "=============================================================================="
    echo "Creating dojo/settings/settings.py file"
    echo "=============================================================================="
    echo
    unset HISTFILE

    if [[ ! -z "$BREW_CMD" ]]; then
        LC_CTYPE=C
    fi

    SECRET=`cat /dev/urandom | LC_CTYPE=C tr -dc "a-zA-Z0-9" | head -c 128`

    # Allow script to be called non-interactively using:
    # export AUTO_DOCKER=yes && /opt/django-DefectDojo/setup.bash
    if [ "$AUTO_DOCKER" == "yes" ]; then
        # locate to the install directory first
        cd $DOJO_ROOT_DIR
    fi

    # Save MySQL details in settings file
    cp dojo/settings/settings.dist.py dojo/settings/settings.py
    sed -i "s/MYSQLHOST/$SQLHOST/g" dojo/settings/settings.py
    sed -i "s/MYSQLPORT/$SQLPORT/g" dojo/settings/settings.py
    sed -i "s/MYSQLUSER/$SQLUSER/g" dojo/settings/settings.py
    sed -i "s/MYSQLPWD/$SQLPWD/g" dojo/settings/settings.py
    sed -i "s/MYSQLDB/$DBNAME/g" dojo/settings/settings.py
    sed -i "s#DOJODIR#$PWD/dojo#g" dojo/settings/settings.py
    sed -i "s/DOJOSECRET/$SECRET/g" dojo/settings/settings.py
    sed -i "s#DOJO_MEDIA_ROOT#$PWD/media/#g" dojo/settings/settings.py
    sed -i "s#DOJO_STATIC_ROOT#$PWD/static/#g" dojo/settings/settings.py

    if [ "$DBTYPE" == "$SQLITE" ]; then
        sed -i "s/BACKENDDB/django.db.backends.sqlite3/g" dojo/settings/settings.py
        sed -i "s/MYSQLDB/db.sqlite3/g" dojo/settings/settings.py
    elif [ "$DBTYPE" == "$MYSQL" ]; then
        sed -i "s/BACKENDDB/django.db.backends.mysql/g" dojo/settings/settings.py
    elif [ "$DBTYPE" == "$POSTGRES" ]; then
        sed -i "s/BACKENDDB/django.db.backends.postgresql_psycopg2/g" dojo/settings/settings.py
    fi
}

function install_app(){
    # Install the app, apply migrations and load data

    # Detect if we're in a a virtualenv
    python -c 'import sys; print sys.real_prefix' 2>/dev/null
    VENV_ACTIVE=$?

    pip install .
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
            $DOJO_DOCKER_DIR/setup-superuser.expect
        fi
    fi

    python manage.py loaddata product_type
    python manage.py loaddata test_type
    python manage.py loaddata development_environment
    python manage.py loaddata system_settings
    python manage.py installwatson
    python manage.py buildwatson

    # Install yarn packages
    PWD_BAK=$PWD
    cd components && yarn && cd $PWD_BAK

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
