# Configuration variables for DefectDojo installs

# Format for setting install config values
# [name of config variable]=${[name of config variable]:-"[default value]"}
# So if you wanted a variable called DD_FOO to default to "BAR" the syntax
# would be:
#    DD_FOO=${DD_FOO:-"BAR"}
# And without an environmental variable called DD_FOO being set before 
# running the install, the value of DD_FOO would be "BAR"
# If you set an environmental variable such as
#    export DD_FOO="BAZ"
# and ran setup.bash, DD_FOO would be "BAZ" instead of the default "BAR"
# 
# This can be used as a template for adding new config variables in future
# D=${D:-"z"}

# Install variables that can be overridden 

########################################################################
# Global vars                                                          #
########################################################################
PROMPT=${PROMPT:-"true"}
INSTALL_TYPE=${INSTALL_TYPE:-"Single Server"}

########################################################################
# DB vars
########################################################################
DB_TYPE=${DB_TYPE:-"MySQL"}  # Valid options: SQLite, MySQL, PostgreSQL
DB_LOCAL=${DB_LOCAL:-"true"}
DB_EXISTS=${DB_EXISTS:-"false"}
DB_ROOT=${DB_ROOT:-"vee0Thoanae1daePooz0ieka"}
DB_NAME=${DB_NAME:-"dojodb"}
DB_USER=${DB_USER:-"dojodbusr"}
DB_PASS=${DB_PASS:-"vee0Thoanae1daePooz0ieka"}
DEV_DB_PASS="vee0Thoanae1daePooz0ieka"
#DEV_DB_PASS="vee0T%oanae1daeP%oz0ieka"
DB_HOST=${DB_HOST:-"localhost"}
DB_PORT=${DB_PORT:-"3306"}
# Drop an existing DB with the same name as above?  true = drop db, false = keep db and exit installer
DB_DROP_EXISTING=${DB_DROP_EXISTING:-"false"} 

########################################################################
# OS vars
########################################################################
OS_USER=${OS_USER:-"dojo-srv"}
OS_PASS=${OS_PASS:-"wahlieboojoKa8aitheibai3"}
DEV_OS_PASS="wahlieboojoKa8aitheibai3"
OS_GROUP=${OS_GROUP:-"dojo-srv"}
INSTALL_ROOT=${INSTALL_ROOT:-"/opt/dojo"}
DOJO_SOURCE=${DOJO_SOURCE:-"$INSTALL_ROOT/django-DefectDojo"}
DOJO_FILES=${DOJO_FILES:-"$INSTALL_ROOT/local"}
MEDIA_ROOT=${MEDIA_ROOT:-"$DOJO_FILES/media"}
STATIC_ROOT=${STATIC_ROOT:-"$DOJO_FILES/static"}
DOJO_ROOT=${DOJO_ROOT:-"$DOJO_SOURCE/dojo"}
#appPath: /opt/dojo/django-DefectDojo/app 

########################################################################
# DefectDojo settings and app vars                                     #
########################################################################

# Meta vars used by installer 
SOURCE_SETTINGS_FILE=${SOURCE_SETTINGS_FILE:-"dojo/settings/settings.dist.py"}
TARGET_SETTINGS_FILE=${TARGET_SETTINGS_FILE:-"dojo/settings/settings.py"}
LOAD_SAMPLE_DATA=${LOAD_SAMPLE_DATA:-"false"}
ENV_SETTINGS_FILE=${ENV_SETTINGS_FILE:-"$REPO_BASE/entrypoint_scripts/common/install-env"} 
ENV_TARGET_FILE=${ENV_TARGET_FILE:-"$REPO_BASE/dojo/settings/.env.prod"}

# Default Dojo Admin user:
ADMIN_USER=${ADMIN_USER:-"admin"}
ADMIN_PASS=${ADMIN_PASS:-"admin"}
DEV_ADMIN_PASS="admin"
ADMIN_EMAIL=${ADMIN_EMAIL:-"ed@example.com"}

# Django settings.py vars
DD_DEBUG=${DD_DEBUG:="False"}                              # Django Debug, defaults to False and should be for production. Can be True or False
DD_DJANGO_ADMIN_ENABLED=${DD_DJANGO_ADMIN_ENABLED:-"True"} # Enables Django Admin, defaults to True - either False or True
DD_SECRET_KEY="GENERATED-DYNAMICALLY-AT-INSTALL-TIME"    # A secret key for a particular Django installation.
DD_CREDENTIAL_AES_256_KEY="GENERATED-DYNAMICALLY-AT-INSTALL-TIME" # Key for encrypting credentials in the manager
DD_DATABASE_URL=${DD_DATABASE_URL:-"mysql://dojodbusr:vee0Thoanae1daePooz0ieka@localhost:3306/dojodb"} # Database URL, options: postgres://, mysql://, sqlite://, to use unsafe characters encode with urllib.parse.encode
DD_ALLOWED_HOSTS=${DD_ALLOWED_HOSTS:-"*"}                # Hosts/domain names that are valid for this site - Separate accepted hosts with a comma for 2+ hostnames
# WhiteNoise allows your web app to serve its own static files,
# making it a self-contained unit that can be deployed anywhere without relying on nginx,
# if using nginx then disable Whitenoise
DD_WHITENOISE=${DD_WHITENOISE:-"True"}   # Valid options: True, False
# Additional Settings / Override defaults in settings.py
DD_TIME_ZONE=${DD_TIME_ZONE:-"America/New_York"}         # Timezone - default America/New_York
DD_TRACK_MIGRATIONS=${DD_TRACK_MIGRATIONS:-"True"}         # Track migrations through source control rather than making migrations locally
DD_SESSION_COOKIE_HTTPONLY=${DD_SESSION_COOKIE_HTTPONLY:-"True"} # Whether to use HTTPOnly flag on the session cookie - either True or False
DD_CSRF_COOKIE_HTTPONLY=${DD_CSRF_COOKIE_HTTPONLY:-"True"} # Whether to use HttpOnly flag on the CSRF cookie - either True or False
DD_SECURE_SSL_REDIRECT=${DD_SECURE_SSL_REDIRECT:-"False"}  # If True, the SecurityMiddleware redirects all non-HTTPS requests to HTTPS - either True or False
DD_CSRF_COOKIE_SECURE=${DD_CSRF_COOKIE_SECURE:-"False"}    # Whether to use a secure cookie for the CSRF cookie - either True or False
DD_SECURE_BROWSER_XSS_FILTER=${DD_SECURE_BROWSER_XSS_FILTER:-"True"} # If True, the SecurityMiddleware sets the X-XSS-Protection: 1; - either True or False
DD_SECURE_CONTENT_TYPE_NOSNIFF=${DD_SECURE_CONTENT_TYPE_NOSNIFF:-"True"} # If True, the SecurityMiddleware sets the X-Content-Type-Options: nosniff;
DD_LANG=${DD_LANG:-"en-us"}                              # Change the default language set
DD_WKHTMLTOPDF=${DD_WKHTMLTOPDF:-"/usr/local/bin/wkhtmltopdf"} # Path to PDF library
DD_TEAM_NAME=${DD_TEAM_NAME:-"Security"}                 # Security team name, used for outgoing emails
DD_ADMINS=${DD_ADMINS:-"dojo-srv@localhost"}             # Admins for log emails, separate with comma for 2+ addresses
DD_PORT_SCAN_CONTACT_EMAIL=${DD_PORT_SCAN_CONTACT_EMAIL:-"dojo-srv@localhost"} # Port scan contact email
DD_PORT_SCAN_RESULT_EMAIL_FROM=${DD_PORT_SCAN_RESULT_EMAIL_FROM:-"dojo-srv@localhost"} # Port scan from email
DD_PORT_SCAN_EXTERNAL_UNIT_EMAIL_LIST=${DD_PORT_SCAN_EXTERNAL_UNIT_EMAIL_LIST:-"dojo-srv@localhost"} # Port scan email list
DD_PORT_SCAN_SOURCE_IP=${DD_PORT_SCAN_SOURCE_IP:-"127.0.0.1"} # Port scan source

#D=${D:-"z"}

########################################################################
# Install variables used internally which can't be overridden          #
########################################################################
SUPPORTED_DBS="SQLite MySQL PostgreSQL"  
INSTALL_OS="linux-gnu"
INSTALL_DISTRO="Ubuntu"
INSTALL_OS_VER="18.04"
YARN_GPG="https://dl.yarnpkg.com/debian/pubkey.gpg"
YARN_REPO="deb https://dl.yarnpkg.com/debian/ stable main"
NODE_URL="https://deb.nodesource.com/setup_6.x"
