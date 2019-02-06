#!/bin/bash
# setup.bash automates installing DefectDojo for the following install types:
#
# - Single server installs
# - Dev installs
# - Stand-alone server installs
# - Container Single server e.g. Docker
# - Container Stand-alone server install e.g. Docker
#
# The setup.bash and supported install methods are documented in depth at
#  https://github.com/DefectDojo/django-DefectDojo/tree/master/entrypoint_scripts
#
# Not addressed:
# - Updates to a new version of DefectDojo
#

# Make sure setup.bash is run from the same directory it is located in
cd ${0%/*}  # same as `cd "$(dirname "$0")"` without relying on dirname
SETUP_BASE=`pwd`
REPO_BASE=${SETUP_BASE%/*}

# Set install config values and load the 'libraries' needed for install
LIB_PATH="$SETUP_BASE/scripts/common"
. "$LIB_PATH/config-vars.sh"     # Set install configuration default values
. "$LIB_PATH/cmd-args.sh"        # Get command-line args and set config values as needed
. "$LIB_PATH/prompt.sh"          # Prompt for config values if install is interactive
. "$LIB_PATH/common-os.sh"       # Determine what OS the installer is running on
. "$LIB_PATH/install-dojo.sh"    # Complete an install of Dojo based on previously run code

# Read command-line arguments, if any and set/override config defaults as needed
#   Function in ./scripts/common/cmd-args.sh
read_cmd_args

# Prompt for config values if install is interactive - the default
#   Function in ./scripts/common/prompt.sh
if [ "$PROMPT" = true ] ; then
    prompt_for_config_vals
else
    init_install_creds
fi

# Check for OS installer is running on and that python version is correct
#   Funcions below in ./scripts/common/common-os.sh
check_install_os
# Bootstrap any programs needed specifically for the installer to run
bootstrap_install
check_python_version

# Do the install - broken into pieces by OS
#   Functions below in ./scripts/common/install-dojo.sh
install_dojo

#echo "Blah is $BLAH"
#echo "DD_ENV is $DD_ENV"
echo ""
echo "=============================================================================="
echo " DEBUG JUNK"
echo "=============================================================================="
echo ""
echo "PROMPT is $PROMPT"
echo "====> "
echo "INSTALL_OS is $INSTALL_OS"
echo "INSTALL_DISTRO is $INSTALL_DISTRO"
echo "INSTALL_OS_VER is $INSTALL_OS_VER"
echo "DOJO_SOURCE is $DOJO_SOURCE"
echo ""
echo "DB_ROOT=$DB_ROOT"
echo "DB_USER=$DB_USER"
echo "DB_PASS=$DB_PASS"
echo "DB_HOST=$DB_HOST"
echo "DB_PORT=$DB_PORT"
echo "DB_NAME=$DB_NAME"
echo "DEV_DB_PASS=$DEV_DB_PASS"
echo "DB URL is:"
echo "$DD_DATABASE_URL"
echo "OS_PASS=$OS_PASS"
echo "DEV_OS_PASS=$DEV_OS_PASS"
echo "ADMIN_PASS=$ADMIN_PASS"
echo "DEV_ADMIN_PASS=$DEV_ADMIN_PASS"
echo "DB URL is:"
echo "$DD_DATABASE_URL"
echo "End of refactoring"

echo "When you're ready to start the DefectDojo server, type in this directory:"
echo ""
echo "    python3 manage.py runserver"

## Echo out important generated variables/passwords from this install

exit

#-----------------------[ Old stuff ]-----------------------#

# Install the actual application
install_app

echo "=============================================================================="
echo
echo "SUCCESS! Now edit your settings.py file in the 'dojo/settings/' directory to complete the installation."
echo
echo "We suggest you consider changing the following defaults:"
echo
echo "    DEBUG = True  # you should set this to False when you are ready for production."
echo "    Uncomment the following lines if you enabled SSL/TLS on your server:"
echo "        SESSION_COOKIE_SECURE = True"
echo "        CSRF_COOKIE_SECURE = True"
echo "        SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')"
echo "        SECURE_SSL_REDIRECT = True"
echo "        SECURE_BROWSER_XSS_FILTER = True"
echo "        django.middleware.security.SecurityMiddleware"
echo
echo "When you're ready to start the DefectDojo server, type in this directory:"
echo
echo "    python manage.py runserver"
echo
