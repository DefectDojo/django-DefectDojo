# DefectDojo install 'library' to handle installing DefectDojo on Linux
# 

function ubuntu_db_install() {
	# Install the database type for this install - SQLite, MySQL, PostgreSQL
	case $DB_TYPE in
	  "SQLite")
	  echo "  Installing SQLite"
	  DEBIAN_FRONTEND=noninteractive sudo apt install -y sqlite3
	  ;;
	  "MySQL")
	  echo "  Installing MySQL"
	  DEBIAN_FRONTEND=noninteractive sudo apt install -y mysql-server libmysqlclient-dev
	  ;;
	  "PostgreSQL")
	  echo "  Installing PostgreSQL"
	  DEBIAN_FRONTEND=noninteractive sudo apt install -y libpq-dev postgresql postgresql-contrib
	  ;;
	  *)
	  echo "    Error: Unsupported DB Type"
	  exit 1
	  ;;
	esac
}

function ubuntu_db_config() {
	## Add a case statement for the DB types
	
	# Start up DB
	if [ "$DB_LOCAL" = true ]; then
	    sudo usermod -d /var/lib/mysql/ mysql
	    sudo mkdir /var/run/mysqld
	    sudo chown -R mysql:mysql /var/lib/mysql /var/run/mysqld
	    sudo service mysql start
	fi
	
	# Check if MySQL DB exists already
	if mysql -fs --protocol=TCP -h "$DB_HOST" -P "$DB_PORT" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" >/dev/null 2>&1 </dev/null; then
	    # DB exists already
	    echo "  Database $DB_NAME already exists!"
	    if [ "$DB_DROP_EXISTING"  = true ]; then
	        # Drop existing DB
	        MYSQL_PWD="$DB_PASS" mysqladmin -f --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" drop "$DB_NAME"
	    else
	        echo "  ERROR: DefectDojo DB exists but DB_DROP_EXISTING is set to $DB_DROP_EXISTING"
	        echo "         Exiting"
	        exit 1
	    fi
	else 
	   # DB does not exist already, set the password for the root user
	   echo "  Setting up root user for new DB install"
	   mysql -u "root" -e "GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost'"
	   mysql -u "root" -e "SET PASSWORD = PASSWORD('${DB_ROOT}');"
	fi
	
	# Create the database for DefectDojo
	echo "  Creating database for DefectDojo"
	# CREATE DATABASE <dbname> CHARACTER SET utf8;
	#if MYSQL_PWD="" mysqladmin --host="$DB_HOST" --port="$DB_PORT" --user="root" create "$DB_NAME"; then
	if MYSQL_PWD="$DB_ROOT" mysql -u root --host="$DB_HOST" --port="$DB_PORT" -e "CREATE DATABASE $DB_NAME CHARACTER SET UTF8;"; then
        # Setup DB user for DefectDojo to use
        echo "  Adding $DB_USER to the DefectDojo database."
        MYSQL_PWD="$DB_ROOT" mysql -u "root" -e "DROP USER '$DB_USER'@'localhost'" >/dev/null 2>&1
        MYSQL_PWD="$DB_ROOT" mysql -u "root" -e "CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
        MYSQL_PWD="$DB_ROOT" mysql -u "root" -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
        MYSQL_PWD="$DB_ROOT" mysql -u "root" -e "FLUSH PRIVILEGES;"
    else
        echo "  ERROR: Failed to create database $DB_NAME. Exiting."
        exit 1
   fi
}

function ubuntu_os_packages() {
	# Install Yarn repo
    curl -sS "$YARN_GPG" | sudo apt-key add -
    echo "$YARN_REPO" | sudo tee /etc/apt/sources.list.d/yarn.list
    
    # Install Node
    curl -sL "$NODE_URL" | sudo -E bash
    
    # Install OS packages needed by Defect Dojo
    sudo apt update
    sudo apt install -y apt-transport-https libjpeg-dev gcc libssl-dev python-dev python-pip nodejs yarn build-essential
}

function ubuntu_wkhtml_install() {
	# Install wkhtmltopdf for report generation
	cd /tmp
	
	# case statement on Ubuntu version built against 18.04 or 16.04
	case $INSTALL_OS_VER in
	    "18.04" | "19")
        wget https://downloads.wkhtmltopdf.org/0.12/0.12.5/wkhtmltox_0.12.5-1.bionic_amd64.deb 
        apt install -y ./wkhtmltox_0.12.5-1.bionic_amd64.deb 
	    ;;
	    "16.04")
	    wget https://downloads.wkhtmltopdf.org/0.12/0.12.5/wkhtmltox_0.12.5-1.xenial_amd64.deb
	    dpkg -i wkhtmltox_0.12.5-1.xenial_amd64.deb 
	    ;;
	    *)
		echo "    Error: Unsupported OS version - $INSTALL_OS_VER"
		exit 1
		;;
	esac
	
	# Clean up
	cd "$DOJO_SOURCE"
    rm /tmp/wkhtmlto*
}

function urlenc() {
	local STRING="${1}"
	echo `python -c "import sys, urllib as ul; print ul.quote_plus('$STRING')"`
	#NEW=`python -c "import sys, urllib as ul; print ul.quote_plus('$STRING')"`
	#echo `echo "$NEW" | sed -e 's/%/^/g'`
}

function create_dojo_settings() {
	# From Aaron's prepare_settings_file()
	echo "=============================================================================="
    echo "Creating dojo/settings/settings.py and .env file"
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
        #SAFE_URL=$(urlenc "$DB_USER")":$DB_PASS@"$(urlenc "$DB_HOST")":"$(urlenc "$DB_PORT")"/"$(urlenc "$DB_NAME")
        SAFE_URL=$(urlenc "$DB_USER")":"$(urlenc "$DB_PASS")"@"$(urlenc "$DB_HOST")":"$(urlenc "$DB_PORT")"/"$(urlenc "$DB_NAME")
        DD_DATABASE_URL="mysql://$SAFE_URL"
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
    
    echo "DB URL is:"
    echo "$DD_DATABASE_URL"
    
    # Questions:
    # (1) OK to remove the env stuff from settings.py if setup.bash handles them natively?
    #     Idea is to use env vars at install time to create settings.py
    #     Using SOURCE_SETTINGS_FILE=${SOURCE_SETTINGS_FILE:-"dojo/settings/settings.matt.py"} in my POC
    # (2) What default do we want for Whitenoise?  on or off???
    # (3) Why was DB config changed to a URL?  I think I'm getting breakage on the URL string with sed
    #     if the generated password has problematic characters
    # (4) I don't see an env variable for DD_EMAIL_URL - is this on purpose?
    #     Also line 302 in settings.matt.py - is that needed?
    # (5) Always do VENV, make it optional or what?
    #
    # Questions round #2
    # (1) Default allowed hosts - empty or ['*']??
    #       https://docs.djangoproject.com/en/2.1/ref/settings/#allowed-hosts
    
    # Substitute install vars for settings.py values
    echo "1"
    sed -i -e 's%#DD_DEBUG#%'$DD_DEBUG'%' "$ENV_TARGET_FILE"
    echo "2"
    sed -i -e 's%#DD_DJANGO_ADMIN_ENABLED#%'$DD_DJANGO_ADMIN_ENABLED'%' "$ENV_TARGET_FILE"
    echo "3"
    sed -i -e 's%#DD_SECRET_KEY#%'$DD_SECRET_KEY'%' "$ENV_TARGET_FILE"
    echo "4"
    sed -i -e 's%#DD_CREDENTIAL_AES_256_KEY#%'$DD_CREDENTIAL_AES_256_KEY'%' "$ENV_TARGET_FILE"
    echo "5"
    sed -i -e "s^#DD_DATABASE_URL#^$DD_DATABASE_URL^" "$ENV_TARGET_FILE"
    echo "6"
    sed -i -e "s%#DD_ALLOWED_HOSTS#%$DD_ALLOWED_HOSTS%" "$ENV_TARGET_FILE" 
    echo "7"
    sed -i -e 's%#DD_WHITENOISE#%'$DD_WHITENOISE'%' "$ENV_TARGET_FILE"
    # Additional Settings / Override defaults in settings.py
    echo "8"
    sed -i -e 's%#DD_TIME_ZONE#%'$DD_TIME_ZONE'%' "$ENV_TARGET_FILE"
    echo "9"
    sed -i -e "s%#DD_TRACK_MIGRATIONS#%$DD_TRACK_MIGRATIONS%" "$ENV_TARGET_FILE"
    echo "10"
    sed -i -e 's%#DD_SESSION_COOKIE_HTTPONLY#%'$DD_SESSION_COOKIE_HTTPONLY'%' "$ENV_TARGET_FILE"
    echo "11"
    sed -i -e 's%#DD_CSRF_COOKIE_HTTPONLY#%'$DD_CSRF_COOKIE_HTTPONLY'%' "$ENV_TARGET_FILE"
    echo "12"
    sed -i -e 's%#DD_SECURE_SSL_REDIRECT#%'$DD_SECURE_SSL_REDIRECT'%' "$ENV_TARGET_FILE"
    echo "13"
    sed -i -e 's%#DD_CSRF_COOKIE_SECURE#%'$DD_CSRF_COOKIE_SECURE'%' "$ENV_TARGET_FILE"
    echo "14"
    sed -i -e 's%#DD_SECURE_BROWSER_XSS_FILTER#%'$DD_SECURE_BROWSER_XSS_FILTER'%' "$ENV_TARGET_FILE"
    echo "15"
    sed -i -e 's%#DD_LANG#%'$DD_LANG'%' "$ENV_TARGET_FILE"
    echo "16"
    sed -i -e 's%#DD_WKHTMLTOPDF#%'$DD_WKHTMLTOPDF'%' "$ENV_TARGET_FILE"
    echo "17"
    sed -i -e 's%#DD_TEAM_NAME#%'$DD_TEAM_NAME'%' "$ENV_TARGET_FILE"
    echo "18"
    sed -i -e 's%#DD_ADMINS#%'$DD_ADMINS'%' "$ENV_TARGET_FILE"
    echo "19"
    sed -i -e 's%#DD_PORT_SCAN_CONTACT_EMAIL#%'$DD_PORT_SCAN_CONTACT_EMAIL'%' "$ENV_TARGET_FILE"
    echo "20"
    sed -i -e 's%#DD_PORT_SCAN_RESULT_EMAIL_FROM#%'$DD_PORT_SCAN_RESULT_EMAIL_FROM'%' "$ENV_TARGET_FILE"
    echo "21"
    sed -i -e 's%#DD_PORT_SCAN_EXTERNAL_UNIT_EMAIL_LIST#%'$DD_PORT_SCAN_EXTERNAL_UNIT_EMAIL_LIST'%' "$ENV_TARGET_FILE"
    echo "22"
    sed -i -e 's%#DD_PORT_SCAN_SOURCE_IP#%'$DD_PORT_SCAN_SOURCE_IP'%' "$ENV_TARGET_FILE"
    echo "23"
    sed -i -e 's%#DD_SECURE_CONTENT_TYPE_NOSNIFF#%'$DD_SECURE_CONTENT_TYPE_NOSNIFF'%' "$ENV_TARGET_FILE"
    # File paths for settings.py
    #sed -i -e 's%#DOJO_ROOT#%'$DOJO_ROOT'%' "$TARGET_SETTINGS_FILE"
    #sed -i -e 's%#MEDIA_ROOT#%'$MEDIA_ROOT'%' "$TARGET_SETTINGS_FILE"
    #sed -i -e 's%#STATIC_ROOT#%'$STATIC_ROOT'%' "$TARGET_SETTINGS_FILE"
    ## NEED TO CHECK HOW THESE END UP !!
}

function ubuntu_dojo_install() {
	echo "=============================================================================="
    echo "Installing DefectDojo Django application "
    echo "=============================================================================="
    echo ""
    
	# Detect if we're in a a virtualenv
    python -c 'import sys; print sys.real_prefix' 2>/dev/null
    VENV_ACTIVE=$?

    # Decide if we always want to install in a VENV
    if [ "$VENV_ACTIVE" = "0" ]; then
        pip install --upgrade pip
        pip install -U pip
        if [ "$DB_TYPE" = MySQL ]; then
            pip install .[mysql]
        else
            pip install .
        fi

    else
        sudo pip install --upgrade pip
        if [ "$DB_TYPE" = MySQL ]; then
            sudo -H pip install .[mysql]
        else
            sudo -H pip install .
        fi
    fi
    
    python manage.py makemigrations dojo
    python manage.py makemigrations --merge --noinput
    python manage.py migrate

    python manage.py createsuperuser --noinput --username="$ADMIN_USER" --email="$ADMIN_EMAIL"
    entrypoint_scripts/common/setup-superuser.expect "$ADMIN_USER" "$ADMIN_PASS"
    

    if [ "$LOAD_SAMPLE_DATA" = true ]; then
      python manage.py loaddata dojo/fixtures/defect_dojo_sample_data.json
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

function install_linux() {
	echo "Inside install_linux"
	
	# Install DB if required
	if [ "$DB_LOCAL" = true ] && [ "$DB_EXISTS" = false ]; then
        # DB is local and needs to be installed	
		case $INSTALL_DISTRO in
		    "Ubuntu" | "Linux Mint")
		    echo "  Installing database on Ubuntu"
		    ubuntu_db_install 
		    ubuntu_db_config
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
	
	# Install OS packages and DefectDojo app
	echo "Install OS packages on $INSTALL_DISTRO"
	case $INSTALL_DISTRO in
	    "Ubuntu" | "Linux Mint")
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
	
	## Final message on the install
}
