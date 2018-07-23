#!/bin/bash
echo
echo "Welcome to DefectDojo! This is a quick script to get you up and running."
echo

# Initialize variables and functions
source entrypoint_scripts/common/dojo-shared-resources.sh
source .env_dojo
verify_cwd
echo "Flushdb is ${FLUSHDB}"
if [[ "${FLUSHDB}" =~ ^[yY]$ ]]; then
  # Create the application DB or recreate it, if it's already present
  # we're opionated here and we only mysql
  ensure_mysql_application_db
  
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
fi

# most times we just start
export C_FORCE_ROOT=True
source .env_dojo
echo "doing stuff" 
wait-for-it/wait-for-it.sh -h mysqldb -p 3306 -t 30
celery -A dojo worker -l info --concurrency 3 &
celery beat -A dojo -l info &
uwsgi --socket :8000 --wsgi-file wsgi.py --workers 7
