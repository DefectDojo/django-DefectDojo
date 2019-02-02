# DefectDojo install 'library' to handle command-line arguments
#

# Function to randomly generate all passwords for credential pairs used by the installer
init_install_creds() {
	# Set creds to random values or hard-code them only for Dev installs
	if [ "$INSTALL_TYPE" = "Dev Install" ]; then
	    # Hardcode passwords for Dev installs so they are consistent
	    echo ""
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	    echo "!  WARNNING: Dev install has hard coded credentials - you have been warned.  !"
	    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	    echo ""
	    DB_PASS="$DEV_DB_PASS"
	    DB_ROOT="$DEV_DB_PASS"
	    OS_PASS="$DEV_OS_PASS"
	    ADMIN_PASS="$DEV_ADMIN_PASS"
	else
	    # Generate a unique password for this install for the database user
	    DB_PASS=`LC_CTYPE=C tr -dc A-Za-z0-9_\!\@\#\$\%\^\&\*\(\)-+ < /dev/urandom | head -c 24`
	    # Generate a unique password for this install for the database root user
	    DB_ROOT=`LC_CTYPE=C tr -dc A-Za-z0-9_\!\@\#\$\%\^\&\*\(\)-+ < /dev/urandom | head -c 24`
	    # Generate a unique password for this install for the OS user
	    OS_PASS=`LC_CTYPE=C tr -dc A-Za-z0-9_\!\@\#\$\%\^\&\*\(\)-+ < /dev/urandom | head -c 24`
	    # Generate a unique password for this install for the dojo admin user
	    ADMIN_PASS=`LC_CTYPE=C tr -dc A-Za-z0-9_\!\@\#\$\%\^\&\*\(\)-+ < /dev/urandom | head -c 24`
	fi

	# Always generate unique values for any install type

	# Generate a unique secret to use in the Django settings.py file per install
	DD_SECRET_KEY=`cat /dev/urandom | LC_CTYPE=C tr -dc "a-zA-Z0-9" | head -c 128`
	# Generate a unique AES key to use in the Django settings.py file per install
	DD_CREDENTIAL_AES_256_KEY=`cat /dev/urandom | LC_CTYPE=C tr -dc "a-zA-Z0-9" | head -c 128`
}

# Function to handle changing database install config options
change_db_config() {
	# Prompt for the various DB options
	echo ""
	echo "=============================================================================="
	echo "  Prompting for DB options"
	echo "=============================================================================="
	echo ""

	ANS="invalid"
	echo ""
	while [ $ANS = "invalid" ]
    do
	    read -p "  Change DB name from $DB_NAME? (1) Yes, (2) No, keep the default: " DB_Q
	    case $DB_Q in
		    1)
		    echo ""
		    read -p "    Enter a new DB name: " DB_NAME
		    ANS="valid"
		    ;;
		    2)
		    echo ""
		    echo "  Keeping DB name of $DB_NAME"
		    ANS="valid"
		    ;;
		    *)
		    echo "    Error: Please enter 1, or 2"
		    ;;
		esac
    done

    ANS="invalid"
    echo ""
	while [ $ANS = "invalid" ]
    do
	    read -p "  Change DB user from $DB_USER (1) Yes, (2) No, keep the default: " DB_Q
	    case $DB_Q in
		    1)
		    echo ""
		    read -p "    Enter a new DB user: " DB_USER
		    ANS="valid"
		    ;;
		    2)
		    echo ""
		    echo "  Keeping DB user of $DB_USER"
		    ANS="valid"
		    ;;
		    *)
		    echo "    Error: Please enter 1, or 2"
		    ;;
		esac
    done

	ANS="invalid"
	echo ""
	while [ $ANS = "invalid" ]
    do
	    read -p "  Change DB password from $DB_PASS (1) Yes, (2) No, keep this password: " DB_Q
	    case $DB_Q in
		    1)
		    echo ""
		    read -p "    Enter a new DB password: " DB_PASS
		    ANS="valid"
		    ;;
		    2)
		    echo ""
		    echo "  Keeping generated DB password of $DB_PASS"
		    ANS="valid"
		    ;;
		    *)
		    echo "    Error: Please enter 1, or 2"
		    ;;
		esac
    done

    # Only ask for host when the DB is remote and exists
    #  otherwise it's going to be localhost (aka local install)
    #  or the remote db doesn't exist and this installed doesn't handle remove DB installs
    if [ "$DB_LOCAL" = false ] && [ "$DB_EXISTS" = true ]; then
	    ANS="invalid"
		echo ""
		while [ $ANS = "invalid" ]
	    do
		    read -p "  Change DB host from $DB_HOST (1) Yes, (2) No, keep the default: " DB_Q
		    case $DB_Q in
			    1)
			    echo ""
			    read -p "    Enter a new DB host: " DB_HOST
			    ANS="valid"
			    ;;
			    2)
			    echo ""
			    echo "  Keeping DB host of $DB_HOST"
			    ANS="valid"
			    ;;
			    *)
			    echo "    Error: Please enter 1, or 2"
			    ;;
			esac
	    done
	fi

	ANS="invalid"
	echo ""
	while [ $ANS = "invalid" ]
    do
	    read -p "  Change DB port from $DB_PORT (1) Yes, (2) No, keep this port number: " DB_Q
	    case $DB_Q in
		    1)
		    echo ""
		    read -p "    Enter a new DB port: " DB_PORT
		    ANS="valid"
		    ;;
		    2)
		    echo ""
		    echo "  Keeping DB port of $DB_PORT"
		    ANS="valid"
		    ;;
		    *)
		    echo "    Error: Please enter 1, or 2"
		    ;;
		esac
    done
}

# Function to handle interactive changes to OS config values
change_os_config() {
	#TODO - finish me
	echo ""
	echo "Prompts for OS configs HERE"
}

# Function to handle interactive changes to DefectDojo's admin login
change_admin_login() {
	#TODO - finish me
	echo ""
	echo "Prompts for DefectDojo's admin login HERE"
}

# Prompt user for config options needed for interactive install
prompt_for_config_vals() {
	echo "=============================================================================="
	echo "  Starting interactive DefectDojo installation"
	echo "=============================================================================="
	echo ""

	# Prompt install type
	ANS="invalid"
	echo "  Choose install type: setup.bash supports the following install types:"
	echo ""
	echo "    (1) Single Server - Everything on one OS/server/container"
	echo ""
	echo "    (2) Dev Install - Single Server install with all default install options "
	echo "        & passwords"
	echo ""
	echo "    (3) Stand-alone Server - DefectDojo installed on a separate OS/server/"
	echo "        container then the database"
	echo ""
	while [ $ANS = "invalid" ]
    do
	    read -p "Select install type: (1) Single-Server, (2) Dev Install or (3) Stand-alone: " IN_Q
	    case $IN_Q in
		    1)
		    INSTALL_TYPE="Single Server"
		    ANS="valid"
		    ;;
		    2)
		    INSTALL_TYPE="Dev Install"
		    init_install_creds
		    # Return accepting all default install config values
		    return
		    ;;
		    3)
		    INSTALL_TYPE="Stand-alone Server"
		    ANS="valid"
		    ;;
		    *)
		    echo "    Error: Please enter 1, 2 or 3"
		    ;;
		esac
    done
    init_install_creds
    echo ""

	# Prompt user for DB type to use
	echo "=============================================================================="
	echo "  Select database type"
	echo "=============================================================================="
	echo ""
	ANS="invalid"
	while [ $ANS = "invalid" ]
    do
	    read -p "Select database type: (1) SQLite, (2) MySQL or (3) PostgreSQL: " DB_Q
	    case $DB_Q in
		    1)
		    DB_TYPE="SQLite"
		    ANS="valid"
		    ;;
		    2)
		    DB_TYPE="MySQL"
		    DB_PORT=${DB_PORT:-"3306"}
		    ANS="valid"
		    ;;
		    3)
		    DB_TYPE="PostgreSQL"
		    DB_PORT=${DB_PORT:-"5432"}
		    ANS="valid"
		    ;;
		    *)
		    echo "    Error: Please enter 1, 2 or 3"
		    ;;
		esac
    done

    # Prompt for local or remote database
    echo ""
	echo "=============================================================================="
	echo "  Select if database is remote or local to this install"
	echo "=============================================================================="
    echo ""
    ANS="invalid"
    while [ $ANS = "invalid" ]
    do
        echo "  Will the $DB_TYPE database be local (on the same OS) or remote for this install?"
		echo ""
        read -p "Select (1) Remote, (2) Local: " DB_Q
        case $DB_Q in
		    1)
		    DB_LOCAL="false"
		    ANS="valid"
		    ;;
		    2)
		    DB_LOCAL="true"
		    ANS="valid"
		    ;;
		    *)
		    echo "    Error: Please enter 1 or 2"
		    ;;
		esac
    done

    # Prompt for existing or new database
    echo ""
	echo "=============================================================================="
	echo "  Select if database should be installed during setup "
	echo "=============================================================================="
    echo ""
    ANS="invalid"
    while [ $ANS = "invalid" ]
    do
        echo "  Will the $DB_TYPE database be installed during setup or does it already exist?"
		echo ""
        read -p "Select (1) Install of $DB_TYPE required, (2) $DB_TYPE server already exists/is running: " DB_Q
        case $DB_Q in
		    1)
		    DB_EXISTS="false"
		    ANS="valid"
		    ;;
		    2)
		    DB_EXISTS="true"
		    ANS="valid"
		    ;;
		    *)
		    echo "    Error: Please enter 1 or 2"
		    ;;
		esac
    done

    # Prompt for dropping any existing Dojo DB
    echo ""
	echo "=============================================================================="
	echo "  Keep existing Defect Dojo database if found? "
	echo "=============================================================================="
    echo ""
    ANS="invalid"
    while [ $ANS = "invalid" ]
    do
        echo "  If the installer finds an existing DefectDojo database, should it be dropped?"
		echo ""
        read -p "Select (1) Drop existing database, (2) Keep existing database & exit: " DB_Q
        case $DB_Q in
		    1)
		    DB_DROP_EXISTING="true"
		    ANS="valid"
		    ;;
		    2)
		    DB_DROP_EXISTING="false"
		    ANS="valid"
		    ;;
		    *)
		    echo "    Error: Please enter 1 or 2"
		    ;;
		esac
    done

	# Sanity check answers, and exit if DB is remote and doesn't exists aka beyond the scope of this installer
	# Case 1: Remote database + database doesn't exist
	if [ "$DB_LOCAL" = false ] && [ "$DB_EXISTS" = false ]; then
	    echo ""
		echo "##############################################################################"
		echo "#  AN ERROR HAS OCCURED                                                      #"
		echo "##############################################################################"
	    echo ""
		echo "  You answered that the $DB_TYPE is remote and doesn't already exist"
	    echo "  This installer cannot do remote installs.  Please install $DB_TYPE"
	    echo "  on the remote system of your choosing then re-run this installer"
	    echo "  Exiting..."
	    echo ""
	    exit 1
	fi

	# Ask if DB defaults are OK for a new, local DB install
	# Case 2: Local database + database doesn't exist
	if [ "$DB_LOCAL" = true ] && [ "$DB_EXISTS" = false ]; then
		echo ""
		echo "=============================================================================="
		echo "  Install settings for local database that needs to be installed "
		echo "=============================================================================="
	    echo ""
	    echo "  Current $DB_TYPE database install config includes:"
	    echo "    Name of database:          $DB_NAME"
	    echo "    User for the database:     $DB_USER"
	    echo "    Password for DB user:      $DB_ROOT"
	    echo "    Password for DB root user: $DB_PASS"
	    echo "    Host:                      $DB_HOST"
	    echo "    Port:                      $DB_PORT"
	    echo ""
	    ANS="invalid"
	    while [ $ANS = "invalid" ]
	    do
	        echo "  Do you want to change any of these values?"
			echo ""
	        read -p "Select (1) Yes, (2) No: " DB_Q
	        case $DB_Q in
			    1)
			    change_db_config
			    ANS="valid"
			    ;;
			    2)
			    echo ""
			    echo "  OK. Keeping default $DB_TYPE configuration values for this install"
			    echo ""
			    ANS="valid"
			    ;;
			    *)
			    echo "    Error: Please enter 1 or 2"
			    ;;
			esac
	    done
	fi

	# Case 3: Local database + database exists
	if [ "$DB_LOCAL" = true ] && [ "$DB_EXISTS" = true ]; then
		echo ""
		echo "=============================================================================="
		echo "  Install settings for local database that already is installed "
		echo "=============================================================================="
		echo ""
	    # Should only need to get config values
	    echo "  Please update database config to reflect the existing local database"
	    change_db_config
	fi

	# Case 4: Remote database + database exists
	if [ "$DB_LOCAL" = false ] && [ "$DB_EXISTS" = true ]; then
		echo ""
		echo "=============================================================================="
		echo "  Install settings for remote database that already exists "
		echo "=============================================================================="
		echo ""
	    # Should only need to get config values
	    echo "  Please update database config to reflect the existing remote database"
	    change_db_config
	fi

	# Ask if OS defaults are OK for this install
	echo ""
	echo "=============================================================================="
	echo "  Install settings for OS configuration "
	echo "=============================================================================="
	echo ""
    echo "  Current OS install config includes:"
    echo "    OS user to run Dojo as:             $OS_USER"
    echo "    Password for OS user:               $OS_PASS"
    echo "    Group for the OS user:              $OS_GROUP"
    echo "    Install root directory:             $INSTALL_ROOT"
    echo "    DefectDojo source directory:        $DOJO_SOURCE"
    echo "    Directory of files created by Dojo: $DOJO_FILES"
    echo "    Directory of uploads/media of Dojo: $MEDIA_ROOT"
    echo "    Directory of static files for Dojo: $STATIC_ROOT"
    echo ""
    ANS="invalid"
    while [ $ANS = "invalid" ]
    do
        echo "  Do you want to change any of these values?"
		echo ""
        read -p "Select (1) Yes, (2) No: " OS_Q
        case $OS_Q in
		    1)
		    change_os_config
		    ANS="valid"
		    ;;
		    2)
		    echo ""
		    echo "  OK. Keeping default OS configuration values for this install"
		    echo ""
		    ANS="valid"
		    ;;
		    *)
		    echo "    Error: Please enter 1 or 2"
		    ;;
		esac
    done

	# Ask if Dojo admin user defaults are OK for this install
	echo ""
	echo "=============================================================================="
	echo "  Install settings for Defect Dojo application configuration "
	echo "=============================================================================="
	echo ""
    echo "  Current admin user config for DefectDojo:"
    echo "    Admin user to log into Dojo:  $ADMIN_USER"
    echo "    Password for the admin user:  $ADMIN_PASS"
    echo "    Email for the admin user:     $ADMIN_EMAIL"
    echo ""
    ANS="invalid"
    while [ $ANS = "invalid" ]
    do
        echo "  Do you want to change any of these values?"
		echo ""
        read -p "Select (1) Yes, (2) No: " AD_Q
        case $AD_Q in
		    1)
		    change_admin_login
		    ANS="valid"
		    ;;
		    2)
		    echo ""
		    echo "  OK. Keeping default admin user config values for this install"
		    echo ""
		    ANS="valid"
		    ;;
		    *)
		    echo "    Error: Please enter 1 or 2"
		    ;;
		esac
    done

	echo ""
	echo "=============================================================================="
	echo "  End of interactive portion of the installer "
	echo "=============================================================================="
	echo ""
}
