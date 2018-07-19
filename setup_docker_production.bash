#!/bin/bash
# setup.bash helps you installing DefectDojo in your current environment
#
# setup.bash covers the following cases (and types of environments):
# - Fresh installs on non-transient environments (physical or virtual OS)
# - Fresh installs on transient environment blueprints (containerized environments)
# - Fresh installs on transient VMs (Vagrant and the like)
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
source .env_dojo
verify_cwd

# Create the application DB or recreate it, if it's already present
ensure_application_db

# Adjust the settings.py file
# we skip this in favor of envfile format
# prepare_settings_file
pushd /django-DefectDojo/dojo/settings
python template.py
popd

# Ensure, we're running on a supported python version
verify_python_version

# Install the actual application
install_app
