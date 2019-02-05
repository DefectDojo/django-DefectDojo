# DefectDojo install 'library' to handle installing DefectDojo on Linux
#

function ubuntu_db_install() {
	# Install the database type for this install - SQLite, MySQL, PostgreSQL
	case $DB_TYPE in
	    "SQLite")
        echo "=============================================================================="
        echo "  Installing SQLite for DefectDojo"
        echo "=============================================================================="
        echo ""
	    DEBIAN_FRONTEND=noninteractive sudo apt install -y sqlite3
        echo ""
	    ;;
	    "MySQL")
        echo "=============================================================================="
        echo "  Installing MySQL for DefectDojo"
        echo "=============================================================================="
        echo ""
	    DEBIAN_FRONTEND=noninteractive sudo apt install -y mysql-server libmysqlclient-dev
        echo ""
	    ;;
	    "PostgreSQL")
        echo "=============================================================================="
        echo "  Installing PostgreSQL for DefectDojo"
        echo "=============================================================================="
        echo ""
	    DEBIAN_FRONTEND=noninteractive sudo apt install -y libpq-dev postgresql postgresql-contrib
        echo ""
	    ;;
	    *)
        echo "##############################################################################"
        echo "#  ERROR: Unsupported or unknown database type                               #"
        echo "##############################################################################"
        echo ""
	    exit 1
	    ;;
	esac
}

function ubuntu_db_config() {
	## TODO: Add a case statement for the DB types or absctract out DB-specific syntax

	# Ensure DB is running by starting it up
	if [ "$DB_LOCAL" = true ]; then
        echo "=============================================================================="
        echo "  Starting $DB_TYPE server"
        echo "=============================================================================="
        echo ""
	    sudo usermod -d /var/lib/mysql/ mysql > /dev/null 2>&1
		if [ ! -d "/var/run/mysqld" ]; then
	        sudo mkdir /var/run/mysqld
		fi
	    sudo chown -R mysql:mysql /var/lib/mysql /var/run/mysqld
	    sudo service mysql start
        echo ""
    # Check that the remote DB is available
    else
        # Just try and run quit in the remote DB - verifies connectivity and creds provided work
        if mysql -fs -h "$DB_HOST" -P "$DB_PORT" -u"$DB_USER" -p"$DB_PASS" -e "quit" > /dev/null 2>&1; then
            echo "=============================================================================="
            echo "  Remote $DB_TYPE server connectivey confirmed"
            echo "=============================================================================="
            echo ""
        else
            echo "##############################################################################"
            echo "#  ERROR: Remote $DB_TYPE server connectivey failed - exiting                #"
            echo "##############################################################################"
            echo ""
            exit 1
        fi
    fi

	# Check if MySQL DB for DefectDojo exists already
    echo "=============================================================================="
    echo "  Checking for existing DefectDojo database $DB_NAME in $DB_TYPE"
    echo "=============================================================================="
    echo ""
    # Handle the case of an existing DB server - either remote or local
    if [ "$DB_EXISTS" = true ]; then
        # For existing DBs, the password provided should work so use it
        if mysqlshow -h "$DB_HOST" -P "$DB_PORT" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" > /dev/null 2>&1; then
            # DB exists already
            echo "=============================================================================="
            echo "  Database named $DB_NAME in $DB_TYPE already exists"
            echo "=============================================================================="
            echo ""
            if [ "$DB_DROP_EXISTING"  = true ]; then
                # Drop existing DB
                echo "=============================================================================="
                echo "  DB_DROP_EXISTING is true, dropping $DB_NAME in $DB_TYPE "
                echo "=============================================================================="
                echo ""
                MYSQL_PWD="$DB_PASS" mysqladmin -f --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" drop "$DB_NAME"
            else
                echo "##############################################################################"
                echo "  ERROR: DB_DROP_EXISTING is false, but $DB_NAME exists - exiting"
                echo "##############################################################################"
                echo ""
                exit 1
            fi
        else
            # DB does not exist in the already running DB server provided to the installer
            # keep using provided credentials
            echo "=============================================================================="
            echo "  Database named $DB_NAME in $DB_TYPE not found, creating..."
            echo "=============================================================================="
            echo ""
            CR_DB="CREATE DATABASE $DB_NAME CHARACTER SET UTF8;"
            if MYSQL_PWD="$DB_PASS" mysql -u $DB_USER -h "$DB_HOST" -P "$DB_PORT" -e "$CR_DB"; then
                # Setup DB user for DefectDojo to use
                echo "=============================================================================="
                echo "  Adding $DB_USER to the DefectDojo database"
                echo "=============================================================================="
                echo ""
                DR_USR="DROP USER '$DB_USER'@'localhost'"
                MYSQL_PWD="$DB_PASS" mysql -u $DB_USER -h "$DB_HOST" -P "$DB_PORT" -e "$DR_USR" >/dev/null 2>&1
                CR_USR="CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
                MYSQL_PWD="$DB_PASS" mysql -u $DB_USER -h "$DB_HOST" -P "$DB_PORT"-e "$CR_USR"
                GR_PRV="GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
                MYSQL_PWD="$DB_PASS" mysql -u $DB_USER -h "$DB_HOST" -P "$DB_PORT" -e "$GR_PRV"
                MYSQL_PWD="$DB_PASS" mysql -u $DB_USER -h "$DB_HOST" -P "$DB_PORT" -e "FLUSH PRIVILEGES;"
            else
                echo "##############################################################################"
                echo "  ERROR: Failed to create $DB_NAME in $DB_TYPE for DefectDojo, exiting..."
                echo "##############################################################################"
                echo ""
                exit 1
            fi
        fi
    # Handle the case of a new DB install which can only be local - remote DB installs are not supported
    else
        # DB install is new so set the password for the root user
        echo "=============================================================================="
        echo "  Seting root password for new $DB_TYPE install"
        echo "=============================================================================="
        echo ""
        mysql -u "root" -e "GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost'"
        mysql -u "root" -e "SET PASSWORD = PASSWORD('${DB_ROOT}');"
        # For newly installe DBs, use root user sincd $DB_USER can't exist yet
        if mysqlshow -h "$DB_HOST" -P "$DB_PORT" -u"root" "$DB_NAME" > /dev/null 2>&1; then
            # DB exists already
            echo "=============================================================================="
            echo "  Database named $DB_NAME in $DB_TYPE already exists"
            echo "=============================================================================="
            echo ""
            if [ "$DB_DROP_EXISTING"  = true ]; then
                # Drop existing DB
                echo "=============================================================================="
                echo "  DB_DROP_EXISTING is true, dropping $DB_NAME in $DB_TYPE "
                echo "=============================================================================="
                echo ""
                mysqladmin -f -h "$DB_HOST" -P "$DB_PORT" -u "root" drop "$DB_NAME"
            else
                echo "##############################################################################"
                echo "  ERROR: DB_DROP_EXISTING is false, but $DB_NAME exists - exiting"
                echo "##############################################################################"
                echo ""
                exit 1
            fi
        else
            # DB does not exist in the new DB server provided to the installer so use root user
            echo "=============================================================================="
            echo "  Database named $DB_NAME in $DB_TYPE not found, creating..."
            echo "=============================================================================="
            echo ""
            CR_DB="CREATE DATABASE $DB_NAME CHARACTER SET UTF8;"
            if MYSQL_PWD="$DB_ROOT" mysql -u "root" -h "$DB_HOST" -P "$DB_PORT" -e "$CR_DB"; then
                # Setup DB user for DefectDojo to use
                echo "=============================================================================="
                echo "  Adding $DB_USER to the DefectDojo database"
                echo "=============================================================================="
                echo ""
                DR_USR="DROP USER '$DB_USER'@'localhost'"
                MYSQL_PWD="$DB_ROOT" mysql -u "root" -h "$DB_HOST" -P "$DB_PORT" -e "$DR_USR" >/dev/null 2>&1
                CR_USR="CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
                MYSQL_PWD="$DB_ROOT" mysql -u "root" -h "$DB_HOST" -P "$DB_PORT" -e "$CR_USR"
                GR_PRV="GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
                MYSQL_PWD="$DB_ROOT" mysql -u "root" -h "$DB_HOST" -P "$DB_PORT" -e "$GR_PRV"
                MYSQL_PWD="$DB_ROOT" mysql -u "root" -h "$DB_HOST" -P "$DB_PORT" -e "FLUSH PRIVILEGES;"
            else
                echo "##############################################################################"
                echo "  ERROR: Failed to create new $DB_NAME in $DB_TYPE for DefectDojo, exiting..."
                echo "##############################################################################"
                echo ""
                exit 1
            fi
        fi
    fi

    # TODO: Remove the debug junk below
#    echo "DB_ROOT=$DB_ROOT"
#    echo "DB_USER=$DB_USER"
#    echo "DB_PASS=$DB_PASS"
#    echo "DB_HOST=$DB_HOST"
#    echo "DB_PORT=$DB_PORT"
#    echo "DB_NAME=$DB_NAME"
#    echo "DEV_DB_PASS=$DEV_DB_PASS"
#    echo "DB URL is:"
#    echo "$DD_DATABASE_URL"
#    echo "DB_EXISTS=$DB_EXISTS"
#    echo ""
}

function ubuntu_os_packages() {
	# Install Yarn repo
    echo "=============================================================================="
    echo "  Add Yarn repo for apt to use"
    echo "=============================================================================="
    echo ""
    curl -sS "$YARN_GPG" | sudo apt-key add - >/dev/null 2>&1
    sudo echo -n "$YARN_REPO" > /etc/apt/sources.list.d/yarn.list

    # Install Node
    echo "=============================================================================="
    echo "  Install Node.js"
    echo "=============================================================================="
    curl -sL "$NODE_URL" | sudo -E bash

    # Install OS packages needed by DefectDojo
    echo "=============================================================================="
    echo "  Install OS packages needed by DefectDojo"
    echo "=============================================================================="
    echo ""
    sudo apt update
    sudo apt install -y apt-transport-https libjpeg-dev gcc libssl-dev python3-dev python3-pip nodejs yarn build-essential
    echo ""
}

function ubuntu_wkhtml_install() {
	# Install wkhtmltopdf for report generation
    echo "=============================================================================="
    echo "  Installing wkhtml for PDF report generation "
    echo "=============================================================================="
    echo ""
	cd /tmp

	# case statement on Ubuntu version built against 18.04 or 16.04
	case $INSTALL_OS_VER in
	    "18.04")
        wget https://downloads.wkhtmltopdf.org/0.12/0.12.5/wkhtmltox_0.12.5-1.bionic_amd64.deb
        apt install -y ./wkhtmltox_0.12.5-1.bionic_amd64.deb
        echo ""
	    ;;
	    "16.04")
	    wget https://downloads.wkhtmltopdf.org/0.12/0.12.5/wkhtmltox_0.12.5-1.xenial_amd64.deb
	    apt install -y ./wkhtmltox_0.12.5-1.xenial_amd64.deb
        echo ""
	    ;;
	    *)
        echo "=============================================================================="
        echo "  Error: Unsupported OS version for wkthml - $INSTALL_OS_VER"
        echo "=============================================================================="
        echo ""
		echo "    Error: Unsupported OS version - $INSTALL_OS_VER"
		exit 1
		;;
	esac

	# Clean up
	cd "$DOJO_SOURCE"
    rm /tmp/wkhtmlto*
}

function urlenc() {
    # URL encode values used in the DB URL to keep certain chars from breaking things
	local STRING="${1}"
	echo `python3 -c "import urllib.parse as ul; print(ul.quote_plus('$STRING'))"`
	#echo `python -c "import sys, urllib as ul; print ul.quote_plus('$STRING')"`
}

function create_dojo_settings() {
	# From Aaron's prepare_settings_file()
	echo "=============================================================================="
    echo "  Creating dojo/settings/settings.py and .env file"
    echo "=============================================================================="
    echo ""

    # Copy settings file & env files to final location
    cp "$SOURCE_SETTINGS_FILE" "$TARGET_SETTINGS_FILE"
    cp "$ENV_SETTINGS_FILE" "$ENV_TARGET_FILE"

    # Construct DD_DATABASE_URL based on DB type - see https://github.com/kennethreitz/dj-database-url
    case $DB_TYPE in
        "SQLite")
        # sqlite:///PATH
        DD_DATABASE_URL="sqlite:///defectdojo.db"
        ;;
        "MySQL")
        # mysql://USER:PASSWORD@HOST:PORT/NAME
        SAFE_URL=$(urlenc "$DB_USER")":"$(urlenc "$DB_PASS")"@"$(urlenc "$DB_HOST")":"$(urlenc "$DB_PORT")"/"$(urlenc "$DB_NAME")
        DD_DATABASE_URL="mysql://$SAFE_URL"
        # TODO
        echo "DD_DATABASE_URL is $DD_DATABASE_URL"
        ;;
        "PostgreSQL")
        # postgres://USER:PASSWORD@HOST:PORT/NAME
        SAFE_URL=$(urlenc "$DB_USER")":"$(urlenc "$DB_PASS")"@"$(urlenc "$DB_HOST")":"$(urlenc "$DB_PORT")"/"$(urlenc "$DB_NAME")
        DD_DATABASE_URL="postgres://$SAFE_URL"
        ;;
        *)
        echo "    Error: Unsupported DB type - $DB_TYPE"
		exit 1
		;;
	esac

    # Substitute install vars for settings.py values
    sed -i -e 's%#DD_DEBUG#%'$DD_DEBUG'%' "$ENV_TARGET_FILE"
    sed -i -e 's%#DD_DJANGO_ADMIN_ENABLED#%'$DD_DJANGO_ADMIN_ENABLED'%' "$ENV_TARGET_FILE"
    sed -i -e 's%#DD_SECRET_KEY#%'$DD_SECRET_KEY'%' "$ENV_TARGET_FILE"
    sed -i -e 's%#DD_CREDENTIAL_AES_256_KEY#%'$DD_CREDENTIAL_AES_256_KEY'%' "$ENV_TARGET_FILE"
    sed -i -e "s^#DD_DATABASE_URL#^$DD_DATABASE_URL^" "$ENV_TARGET_FILE"
    sed -i -e "s%#DD_ALLOWED_HOSTS#%$DD_ALLOWED_HOSTS%" "$ENV_TARGET_FILE"
    sed -i -e 's%#DD_WHITENOISE#%'$DD_WHITENOISE'%' "$ENV_TARGET_FILE"
    # Additional Settings / Override defaults in settings.py
    sed -i -e 's%#DD_TIME_ZONE#%'$DD_TIME_ZONE'%' "$ENV_TARGET_FILE"
    sed -i -e "s%#DD_TRACK_MIGRATIONS#%$DD_TRACK_MIGRATIONS%" "$ENV_TARGET_FILE"
    sed -i -e 's%#DD_SESSION_COOKIE_HTTPONLY#%'$DD_SESSION_COOKIE_HTTPONLY'%' "$ENV_TARGET_FILE"
    sed -i -e 's%#DD_CSRF_COOKIE_HTTPONLY#%'$DD_CSRF_COOKIE_HTTPONLY'%' "$ENV_TARGET_FILE"
    sed -i -e 's%#DD_SECURE_SSL_REDIRECT#%'$DD_SECURE_SSL_REDIRECT'%' "$ENV_TARGET_FILE"
    sed -i -e 's%#DD_CSRF_COOKIE_SECURE#%'$DD_CSRF_COOKIE_SECURE'%' "$ENV_TARGET_FILE"
    sed -i -e 's%#DD_SECURE_BROWSER_XSS_FILTER#%'$DD_SECURE_BROWSER_XSS_FILTER'%' "$ENV_TARGET_FILE"
    sed -i -e 's%#DD_LANG#%'$DD_LANG'%' "$ENV_TARGET_FILE"
    sed -i -e 's%#DD_WKHTMLTOPDF#%'$DD_WKHTMLTOPDF'%' "$ENV_TARGET_FILE"
    sed -i -e 's%#DD_TEAM_NAME#%'$DD_TEAM_NAME'%' "$ENV_TARGET_FILE"
    sed -i -e 's%#DD_ADMINS#%'$DD_ADMINS'%' "$ENV_TARGET_FILE"
    sed -i -e 's%#DD_PORT_SCAN_CONTACT_EMAIL#%'$DD_PORT_SCAN_CONTACT_EMAIL'%' "$ENV_TARGET_FILE"
    sed -i -e 's%#DD_PORT_SCAN_RESULT_EMAIL_FROM#%'$DD_PORT_SCAN_RESULT_EMAIL_FROM'%' "$ENV_TARGET_FILE"
    sed -i -e 's%#DD_PORT_SCAN_EXTERNAL_UNIT_EMAIL_LIST#%'$DD_PORT_SCAN_EXTERNAL_UNIT_EMAIL_LIST'%' "$ENV_TARGET_FILE"
    sed -i -e 's%#DD_PORT_SCAN_SOURCE_IP#%'$DD_PORT_SCAN_SOURCE_IP'%' "$ENV_TARGET_FILE"
    # File paths for settings.py
    #sed -i -e 's%#DOJO_ROOT#%'$DOJO_ROOT'%' "$TARGET_SETTINGS_FILE"
    #sed -i -e 's%#MEDIA_ROOT#%'$MEDIA_ROOT'%' "$TARGET_SETTINGS_FILE"
    #sed -i -e 's%#STATIC_ROOT#%'$STATIC_ROOT'%' "$TARGET_SETTINGS_FILE"
    ## NEED TO CHECK HOW THESE END UP !!
}

function ubuntu_dojo_install() {
    echo "=============================================================================="
    echo "  Installing DefectDojo Django application "
    echo "=============================================================================="
    echo ""

    # TODO: Clean this function up a bit more
	# Detect if we're in a a virtualenv
    python3 -c 'import sys; print sys.real_prefix' 2>/dev/null
    VENV_ACTIVE=$?

    # TODO: Decide if we always want to install in a VENV
    if [ "$VENV_ACTIVE" = "0" ]; then
        #pip3 install --upgrade pip
        #pip3 install -r requirements.txt
        if [ "$DB_TYPE" = MySQL ]; then
            sudo -H pip3 install -r $SETUP_BASE/mysql.txt
        #TODO Add PostgreSQL here
        fi
    else
        #sudo pip3 install --upgrade pip
        #sudo pip3 install -r requirements.txt
        if [ "$DB_TYPE" = MySQL ]; then
            sudo -H pip3 install -r $SETUP_BASE/mysql.txt
        #TODO Add PostgreSQL here
        fi
    fi

    echo "BEFORE DJANGO JUNK"
    cd $REPO_BASE
    python3 manage.py makemigrations dojo
    python3 manage.py makemigrations --merge --noinput
    python3 manage.py migrate

    python3 manage.py createsuperuser --noinput --username="$ADMIN_USER" --email="$ADMIN_EMAIL"
    $SETUP_BASE/scripts/common/setup-superuser.expect "$ADMIN_USER" "$ADMIN_PASS"
    #exit
    

    if [ "$LOAD_SAMPLE_DATA" = true ]; then
      python3 manage.py loaddata dojo/fixtures/defect_dojo_sample_data.json
    fi
    
    python3 manage.py loaddata product_type
    python3 manage.py loaddata test_type
    python3 manage.py loaddata development_environment
    python3 manage.py loaddata system_settings
    python3 manage.py loaddata benchmark_type
    python3 manage.py loaddata benchmark_category
    python3 manage.py loaddata benchmark_requirement
    python3 manage.py loaddata language_type
    python3 manage.py loaddata objects_review
    python3 manage.py loaddata regulation
    
    python3 manage.py installwatson
    python3 manage.py buildwatson

    # Install yarn packages
    cd components && yarn && cd ..

    python3 manage.py collectstatic --noinput
}

function install_linux() {
    echo "=============================================================================="
    echo "  Beginning $INSTALL_DISTRO installation"
    echo "=============================================================================="
    echo ""

	# Install DB if required
	if [ "$DB_LOCAL" = true ] && [ "$DB_EXISTS" = false ]; then
        # DB is local and needs to be installed
		case $INSTALL_DISTRO in
		    "Ubuntu")
		    ubuntu_db_install
		    ;;
		    "centos")
		    echo "  Installing database on CentOS"
		    echo "  TBD: DB install for CentOS"
		    ;;
		    *)
		    echo "    Error: Unsupported OS"
		    exit 1
		    ;;
		esac

	fi

	# Configure the database
    case $INSTALL_DISTRO in
        "Ubuntu")
        ubuntu_db_config
        ;;
        "centos")
        echo "  Configuring the database on CentOS"
        echo "  TBD: DB install for CentOS"
        ;;
        *)
        echo "    Error: Unsupported OS"
        exit 1
        ;;
    esac

	# Install OS packages and DefectDojo app
    echo "=============================================================================="
    echo "  Install OS packages on $INSTALL_DISTRO"
    echo "=============================================================================="
    echo ""
	case $INSTALL_DISTRO in
	    "Ubuntu")
	    # OS Packages needed by DefectDojo
	    ubuntu_os_packages
	    ubuntu_wkhtml_install
	    # Install DefectDojo
	    create_dojo_settings
	    ubuntu_dojo_install
	    ;;
        "centos")
        echo "  Installing database on CentOS"
		echo "  TBD: DB install for CentOS"
		;;
		*)
		echo "    Error: Unsupported OS"
		exit 1
		;;
  	esac
}
