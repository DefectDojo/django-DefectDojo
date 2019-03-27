#!/bin/sh
# This script can be used as an entrypoint to get the Docker image started as
# follows:
#
#   ``docker run -it -p 8000:8000 appsecpipeline/django-defectdojo bash -c "export LOAD_SAMPLE_DATA=True && bash /opt/django-DefectDojo/docker/docker-startup.bash"``
#
# Run it at the application root
#

source entrypoint_scripts/common/dojo-shared-resources.sh

# This function invocation ensures we're running the script at the right place
verify_cwd

########### Setup and Run Entry #############
if [ "$1" == "setup" ]; then
    setupdojo
    chown -R dojo:dojo $DOJO_ROOT_DIR
else
  echo "=============================================================================="
  echo "Starting DefectDojo"
  echo "=============================================================================="
  echo
  if [ -z "$PORT" ]; then
    PORT=8000
  fi

  source $DOJO_VENV_NAME/bin/activate

  unset HISTFILE

  #Checking if local or 3 tier setup
  if [ "$RUN_TIERED" = True ]; then
    echo "=============================================================================="
    echo "Checking the Database is up and accepting connections"
    echo "=============================================================================="
    echo
    #Make sure MySQL is up and running, run the mysql script to check the port and report back
    bash ./wait-for-it.sh $DD_DATABASE_HOST:$DD_DATABASE_PORT

    if [ $? -eq 0 ]; then
      echo "Database server is up and running."
      echo
      if [ $(mysql -N -s -u$DD_DATABASE_USER -p$DD_DATABASE_PASSWORD $DD_DATABASE_NAME --host $DD_DATABASE_HOST --port $DD_DATABASE_PORT -e \
          "select count(*) from information_schema.tables where table_schema='$DD_DATABASE_NAME' and table_name='dojo_product';") -eq 1 ]; then
          echo "DB Exists."
      else
        setupdb
        createadmin
      fi
      echo "=============================================================================="
      echo "Starting Gunicorn"
      echo "=============================================================================="
      echo
      #Start gunicorn
      cd $DOJO_ROOT_DIR
      gunicorn --env DJANGO_SETTINGS_MODULE=dojo.settings.settings dojo.wsgi:application --bind 0.0.0.0:$PORT --workers 3 & celery -A dojo worker -l info --concurrency 3
    else
      echo "MySQL server is down or dojo can't access mysql"
      echo "Exiting startup script..."
      exit 1
    fi
  else
    #Setup admin login and load data
    if [ ! -f setupcomplete ];
    then
      createadmin
      bash docker/dojo-data.bash load
      touch setupcomplete
    fi

    echo "=============================================================================="
    echo "Login with $DOJO_ADMIN_USER/$DD_DATABASE_USER"
    echo "URL: http://localhost:$PORT"
    echo "=============================================================================="
    echo
    echo "=============================================================================="
    echo "Starting Python  Server"
    echo "=============================================================================="
    echo

    source $DOJO_VENV_NAME/bin/activate
    pip freeze
    python manage.py runserver 0.0.0.0:$PORT & celery -A dojo worker -l info --concurrency 3
    echo
  fi
fi
