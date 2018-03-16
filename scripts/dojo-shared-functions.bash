#!/usr/bin/env bash
#####################################################################################
#####
##### Shared set of functions for setting up dojo
#####
#####################################################################################

createadmin() {
  echo "=============================================================================="
  echo "Creating Dojo Admin User"
  echo "=============================================================================="
  echo

  #setup default admin dojo user
  if [ -z "$DOJO_ADMIN_USER" ]; then
    DOJO_ADMIN_USER='admin'
  fi
  if [ -z "$DOJO_ADMIN_EMAIL" ]; then
    DOJO_ADMIN_EMAIL='admin@localhost.local'
  fi
  if [ -z "$DOJO_ADMIN_PASSWORD" ]; then
    DOJO_ADMIN_PASSWORD=`LC_CTYPE=C tr -dc A-Za-z0-9_\!\@\#\$\%\^\&\*\(\)-+ < /dev/urandom | head -c 32 | xargs`
  fi
  #creating default admin user
  echo "from django.contrib.auth.models import User; User.objects.create_superuser('$DOJO_ADMIN_USER', '$DOJO_ADMIN_EMAIL', '$DOJO_ADMIN_PASSWORD')" | ./manage.py shell
}

setupdb() {
  echo "=============================================================================="
  echo "Setting up dojo"
  echo "=============================================================================="
  echo
  cd /django-DefectDojo/
  python manage.py migrate
  python manage.py syncdb --noinput
  python manage.py loaddata product_type
  python manage.py loaddata test_type
  python manage.py loaddata development_environment
  python manage.py loaddata system_settings
  python manage.py installwatson
  python manage.py buildwatson

  echo "=============================================================================="
  echo "Collect Static Files"
  echo "=============================================================================="
  echo
  #Collect static files
  cd /django-DefectDojo/
  python manage.py collectstatic --noinput

  echo "=============================================================================="
  echo "Checking if sample data should be loaded"
  echo "=============================================================================="
  echo
  if [ "$LOAD_SAMPLE_DATA" = True ]; then
    echo
    echo "Loading sample data..."
    bash /django-DefectDojo/docker/dojo-data.bash load
    echo
  fi
}

setupdojo() {
  echo "=============================================================================="
  echo "DefectDojo Docker Setup"
  echo "Installing required packages"
  echo "=============================================================================="
  echo

  echo "=============================================================================="
  echo "Installing Bower"
  echo "=============================================================================="
  echo
  # bower install
  npm install -g bower

  echo "=============================================================================="
  echo "Creating Virtual Environment"
  echo "=============================================================================="
  echo
  #Create virtual environment
  cd /django-DefectDojo
  #Remove any previous virtual environments
  if [ -d venv ];
  then
    rm -r venv
  fi
  virtualenv venv
  source venv/bin/activate

  # Detect Python version
  PYV=`python -c "import sys;t='{v[0]}.{v[1]}'.format(v=list(sys.version_info[:2]));sys.stdout.write(t)";`
  if [[ "$PYV"<"2.7" ]]; then
      echo "ERROR: DefectDojo requires Python 2.7+"
      exit 1;
  else
      echo "Leaving Django 1.x.y requirement"
  fi

  echo "=============================================================================="
  echo "Pip install required components"
  echo "=============================================================================="
  echo
  pip install .

  echo "=============================================================================="
  echo "Copying settings.py"
  echo "=============================================================================="
  echo
  #Copying setting.py temporarily so that collect static will run correctly
  cp /django-DefectDojo/dojo/settings/settings_dist.py /django-DefectDojo/dojo/settings/settings.py
  sed -i  "s#DOJO_STATIC_ROOT#$PWD/static/#g" /django-DefectDojo/dojo/settings/settings.py

  echo "Setting dojo settings for SQLLITEDB."
  SQLLITEDB="'NAME': os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'db.sqlite3')"
  sed -i  "s/django.db.backends.mysql/django.db.backends.sqlite3/g" dojo/settings/settings.py
  sed -i  "s/'NAME': 'MYSQLDB'/$SQLLITEDB/g" dojo/settings/settings.py

  echo "=============================================================================="
  echo "Installing bower"
  echo "=============================================================================="
  echo
  cd /django-DefectDojo/components
  bower install --allow-root

  setupdb

  echo "=============================================================================="
  echo "Removing temporary files"
  echo "=============================================================================="
  #echo
  rm /django-DefectDojo/dojo/settings/settings.py

  echo "=============================================================================="
  echo "SUCCESS!"
  echo "=============================================================================="
}
