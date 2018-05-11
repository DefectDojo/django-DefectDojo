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

#Set the SQL variables
SQLUSER=$MYSQL_USER
SQLPWD=$MYSQL_PASSWORD
SQLHOST=$DOJO_MYSQL_HOST
DBNAME=$MYSQL_DATABASE

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

  #Check to see if Dojo has been setup by checking the settings.py file
  if [ ! -f dojo/settings/settings.py ];
  then
    echo "=============================================================================="
    echo "Creating dojo/settings/settings.py file"
    echo "=============================================================================="
    echo
    unset HISTFILE

    SECRET=`cat /dev/urandom | tr -dc "a-zA-Z0-9" | head -c 128`

    cp dojo/settings/settings_dist.py dojo/settings/settings.py

    # Save MySQL details in settings file
    sed -i "s/MYSQLUSER/$SQLUSER/g" dojo/settings/settings.py
    sed -i "s/MYSQLPWD/$SQLPWD/g" dojo/settings/settings.py
    sed -i "s/MYSQLDB/$DBNAME/g" dojo/settings/settings.py
    sed -i "s/MYSQLHOST/$DOJO_MYSQL_HOST/g" dojo/settings/settings.py
    sed -i "s/MYSQLPORT/$DOJO_MYSQL_PORT/g" dojo/settings/settings.py
    sed -i "s#DOJODIR#$PWD/dojo#g" dojo/settings/settings.py
    sed -i "s/DOJOSECRET/$SECRET/g" dojo/settings/settings.py
    sed -i "s#DOJOURLPREFIX#$DOJO_URL_PREFIX#g" dojo/settings/settings.py
    sed -i "s#BOWERDIR#$PWD/components#g" dojo/settings/settings.py
    sed -i "s#DOJO_MEDIA_ROOT#$PWD/media/#g" dojo/settings/settings.py
    sed -i "s#DOJO_STATIC_ROOT#$PWD/static/#g" dojo/settings/settings.py

    if [ "$RUN_TIERED" = True ]; then
      echo "Setting dojo settings for tiered docker-compose."
      sed -i "s/TEMPLATE_DEBUG = DEBUG/TEMPLATE_DEBUG = False/g" dojo/settings/settings.py
      sed -i "s/DEBUG = True/DEBUG = False/g" dojo/settings/settings.py
      sed -i "s/ALLOWED_HOSTS = \[]/ALLOWED_HOSTS = ['localhost', '127.0.0.1']/g" dojo/settings/settings.py
    else
      echo "Setting dojo settings for SQLLITEDB."
      SQLLITEDB="'NAME': os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'db.sqlite3')"
      sed -i "s/django.db.backends.mysql/django.db.backends.sqlite3/g" dojo/settings/settings.py
      sed -i "s/'NAME': '$DBNAME'/$SQLLITEDB/g" dojo/settings/settings.py
    fi
  fi

  #Checking if local or 3 tier setup
  if [ "$RUN_TIERED" = True ]; then
    echo "=============================================================================="
    echo "Checking the Database is up and accepting connections"
    echo "=============================================================================="
    echo
    #Make sure MySQL is up and running, run the mysql script to check the port and report back
    bash $DOCKER_DIR/wait-for-it.sh $DOJO_MYSQL_HOST:$DOJO_MYSQL_PORT

    if [ $? -eq 0 ]; then
      echo "Database server is up and running."
      echo
      if [ $(mysql -N -s -u$MYSQL_USER -p$MYSQL_PASSWORD $MYSQL_DATABASE --host $DOJO_MYSQL_HOST -e \
          "select count(*) from information_schema.tables where table_schema='$MYSQL_DATABASE' and table_name='dojo_product';") -eq 1 ]; then
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
      gunicorn --env DJANGO_SETTINGS_MODULE=dojo.settings dojo.wsgi:application --bind 0.0.0.0:$PORT --workers 3 & celery -A dojo worker -l info --concurrency 3
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
      bash $DOCKER_DIR/dojo-data.bash load
      touch setupcomplete
    fi

    echo "=============================================================================="
    echo "Login with $DOJO_ADMIN_USER/$DOJO_ADMIN_PASSWORD"
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
