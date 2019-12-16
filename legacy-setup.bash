#!/bin/bash
# setup.bash helps you installing DefectDojo in your current environment
#
# setup.bash covers the following cases (and types of environments):
# - Fresh installs on non-transient environments (physical or virtual OS)
# - Fresh installs on transient environment blueprints (containerized environments)
# - Updates on non-transient environments
#
# Not (yet) addressed:
# - Updates for transient environments
#

echo
echo "Welcome to DefectDojo! This is a quick script to get you up and running."
echo

# Initialize variables and functions
source entrypoint_scripts/common/dojo-shared-resources.sh

# This function invocation ensures we're running the script at the right place
verify_cwd

if [ "$BATCH_MODE" == "yes" ]; then
    setup_batch_mode
else
    prompt_db_type
fi

echo
echo "NEED SUDO PRIVILEGES FOR NEXT STEPS!"
echo
echo "Installing required packages..."
echo

# Install OS dependencies like DB client, further package managers, etc.
install_os_dependencies

# Install database-related packages
install_db

# Create the application DB or recreate it, if it's already present
ensure_application_db

if [ -z "$BATCH_MODE" ]; then
  # Adjust the settings.py file
  prepare_settings_file
fi

# Ensure, we're running on a supported python version
verify_python_version

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
echo "        SECURE_CONTENT_TYPE_NOSNIFF = True"
echo "        django.middleware.security.SecurityMiddleware"
echo
echo "When you're ready to start the DefectDojo server, type in this directory:"
echo
echo "    python manage.py runserver"
echo
