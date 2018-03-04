#!/bin/bash

# Initialize variables and functions
source entrypoint_scripts/common/dojo-build-env.sh
source entrypoint_scripts/common/dojo-shared-functions.bash

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

# Install OS dependencies like a DB client, further package managers, etc
install_os_dependencies
install_db

if [ "$AUTO_DOCKER" == "yes" ]; then
    sudo service mysql start
fi
# Create the application DB or recreate it, if it's already present
ensure_application_db

prepare_settings_file

verify_python_version

install_app

if [ "$AUTO_DOCKER" == "yes" ]; then
    sudo service mysql stop
fi

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
