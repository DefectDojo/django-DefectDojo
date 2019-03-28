#!/bin/bash
#

travis_fold() {
  local action=$1
  local name=$2
  echo -en "travis_fold:${action}:${name}\r"
}

travis_fold start dojo_container_build
echo
echo "DefectDojo Docker Install"
echo

# Initialize variables and functions
source entrypoint_scripts/common/dojo-shared-resources.sh

# This function invocation ensures we're running the script at the right place
verify_cwd

if [ "$FUNCTION" == "dependencies" ]; then
  echo
  echo "Installing required packages..."
  echo
  # Install OS dependencies including the DB client, further package managers, etc.
  install_os_dependencies
elif [ "$FUNCTION" == "db" ]; then
  echo
  echo "Install database-related packages..."
  echo
  install_db

  echo
  echo "Create the application DB or recreate it, if it's already present"
  echo
  ensure_application_db

  echo
  echo "Adjust the settings.py and .env.prod file"
  echo
  prepare_settings_file

  echo
  echo "Install DefectDojo"
  echo
  install_app

  if [ "$DBTYPE" == "$MYSQL" ]; then
    stop_local_mysql_db_server
    set_random_mysql_db_pwd
  fi

  echo
  echo "Running OS upgrade"
  echo
  upgrade

elif [ "$FUNCTION" == "release" ]; then
  remove_install_artifacts
  install_postgres_client
  slim_defect_dojo_settings
fi

echo
echo "Docker step $FUNCTION complete"
echo
travis_fold end dojo_container_build
