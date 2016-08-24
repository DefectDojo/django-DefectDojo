#!/bin/bash
echo "=============================================================================="
echo "Starting DefectDojo"
echo "=============================================================================="
echo

#Set the SQL variables from the .env file
SQLUSER=$MYSQL_USER
SQLPWD=$MYSQL_PASSWORD
SQLHOST=$DOJO_MYSQL_HOST
DBNAME=$MYSQL_DATABASE

cd /django-DefectDojo/
#Check to see if Dojo has been setup by checking the settings.py file
if [ ! -f dojo/settings.py ];
then
  echo "=============================================================================="
  echo "Creating dojo/settings.py file"
  echo "=============================================================================="
  echo
  unset HISTFILE

  SECRET=`cat /dev/urandom | tr -dc "a-zA-Z0-9" | head -c 128`

  cp dojo/settings.dist.py dojo/settings.py

  # Save MySQL details in settings file
  sed -i  "s/MYSQLUSER/$SQLUSER/g" dojo/settings.py
  sed -i  "s/MYSQLPWD/$SQLPWD/g" dojo/settings.py
  sed -i  "s/MYSQLDB/$DBNAME/g" dojo/settings.py
  sed -i  "s/MYSQLHOST/$DOJO_MYSQL_HOST/g" dojo/settings.py
  sed -i  "s/MYSQLPORT/$DOJO_MYSQL_PORT/g" dojo/settings.py
  sed -i  "s#DOJODIR#$PWD/dojo#g" dojo/settings.py
  sed -i  "s/DOJOSECRET/$SECRET/g" dojo/settings.py
  sed -i  "s#DOJOURLPREFIX#$DOJO_URL_PREFIX#g" dojo/settings.py
  sed -i  "s#BOWERDIR#$PWD/components#g" dojo/settings.py
  sed -i  "s#DOJO_MEDIA_ROOT#$PWD/media/#g" dojo/settings.py
  sed -i  "s#DOJO_STATIC_ROOT#$PWD/static/#g" dojo/settings.py
fi

echo "=============================================================================="
echo "Checking that the Database is up and accepting connections"
echo "=============================================================================="
echo
#Make sure MySQL is up and running, run the mysql script to check the port and report back
chmod +x /django-DefectDojo/docker/wait-for-it.sh
bash /django-DefectDojo/docker/wait-for-it.sh $DOJO_MYSQL_HOST:$DOJO_MYSQL_PORT

if [ $? -eq 0 ]; then
  echo "Database server is up and running."
  echo
  if [ $(mysql -N -s -u$MYSQL_USER -p$MYSQL_PASSWORD $MYSQL_DATABASE --host $DOJO_MYSQL_HOST -e \
      "select count(*) from information_schema.tables where table_schema='$MYSQL_DATABASE' and table_name='dojo_product';") -eq 1 ]; then
      echo "DB Exists."
  else
    echo "=============================================================================="
    echo "Setting up dojo"
    echo "=============================================================================="
    echo
    cd /django-DefectDojo/
    python manage.py makemigrations dojo
    python manage.py makemigrations
    python manage.py migrate
    python manage.py syncdb --noinput
    python manage.py loaddata product_type
    python manage.py loaddata test_type
    python manage.py loaddata development_environment
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
    echo "Creating Default Dojo Admin User from .env"
    echo "=============================================================================="
    echo
    #creating default admin user
    echo "from django.contrib.auth.models import User; User.objects.create_superuser('$DOJO_ADMIN_USER', '$DOJO_ADMIN_EMAIL', '$DOJO_ADMIN_PASSWORD')" | ./manage.py shell

  fi
else
  echo "MySQL server is down or dojo can't access mysql"
  echo "Exiting startup script..."
  exit 1
fi

echo "=============================================================================="
echo "Starting Gunicorn"
echo "=============================================================================="
echo
#Start gunicorn
cd /django-DefectDojo/
gunicorn --env DJANGO_SETTINGS_MODULE=dojo.settings dojo.wsgi:application --bind 0.0.0.0:8000 --workers 3 & celery -A dojo worker -l info --concurrency 3

echo "=============================================================================="
echo "Startup Complete"
echo "=============================================================================="
