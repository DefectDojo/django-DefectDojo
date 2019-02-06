#!/bin/bash
echo
echo "=============================================================================="
echo " Starting DefectDojo"
echo "=============================================================================="
echo
# Set the default port
if [[ -z $PORT ]]; then
  PORT=8000
fi

# Check to see if the env file is setup
if cat dojo/settings/.env.prod | grep -q "mysql://root:dojodb_install@localhost:3306/dojodb"; then
	echo
	echo "=============================================================================="
	echo " Adjusting container settings"
	echo "=============================================================================="
	echo
	source entrypoint_scripts/common/dojo-shared-resources.sh

	# Reset mysql password
	set_random_mysql_db_pwd
	DBTYPE=1
	DEFECT_DOJO_DEFAULT_DATABASE_USER=root
	DEFECT_DOJO_DEFAULT_DATABASE_HOST=localhost
	DEFECT_DOJO_DEFAULT_DATABASE_PORT=3306
	DEFECT_DOJO_DEFAULT_DATABASE_NAME=dojodb

	# Set the settings file
	prepare_settings_file

	# Reset admin user or use user supplied password
	if [[ -z $DEFECT_DOJO_ADMIN_PASSWORD ]]; then
		DB_ROOT_PASS_LEN=`shuf -i 20-25 -n 1`
	  DEFECT_DOJO_ADMIN_PASSWORD=`pwgen -scn $DB_ROOT_PASS_LEN 1`
	fi
  sudo chown -R mysql:mysql /var/lib/mysql /var/run/mysqld \
  && sudo service mysql start
	entrypoint_scripts/common/setup-superuser.expect admin "$DEFECT_DOJO_ADMIN_PASSWORD"

	#DB_ROOT_PASS_USER=`pwgen -scn $DB_ROOT_PASS_LEN 1`
	#entrypoint_scripts/common/setup-superuser.expect product_manager "$DEFECT_DOJO_ADMIN_PASSWORD"

	#DEFECT_DOJO_DEFAULT_DATABASE_PASSWORD=`pwgen -scn $DB_ROOT_PASS_LEN 1`
	#entrypoint_scripts/common/setup-superuser.expect user2 "$DEFECT_DOJO_DEFAULT_DATABASE_PASSWORD"

	echo
	echo "=============================================================================="
	echo " SUCCESS! Please login at: http://localhost:$PORT"
	echo " admin / $DEFECT_DOJO_ADMIN_PASSWORD"
	echo "=============================================================================="
	echo
else
  # Startup DefectDojo Services #
  sudo chown -R mysql:mysql /var/lib/mysql /var/run/mysqld \
  && sudo service mysql start
fi

if [[ -z $ACTION ]]; then
  ACTION="a"
fi
if [ "$ACTION" == "c" ] || [ "$ACTION" == "a" ] ; then
	if [ "$ACTION" == "a" ] ; then
  	celery -A dojo worker -l info --concurrency 3 >> /opt/django-DefectDojo/worker.log 2>&1 &
	else
		celery -A dojo worker -l info --concurrency 3
	fi
fi
if [ "$ACTION" == "b" ] || [ "$ACTION" == "a" ] ; then
  if [ "$ACTION" == "a" ] ; then
  	celery beat -A dojo -l info  >> /opt/django-DefectDojo/beat.log 2>&1 &
	else
		celery beat -A dojo -l info  >> /opt/django-DefectDojo/beat.log
	fi
fi
if [ "$ACTION" == "p" ] || [ "$ACTION" == "a" ] ; then
	if [ "$ACTION" == "a" ] ; then
  	python manage.py runserver 0.0.0.0:$PORT>> /opt/django-DefectDojo/dojo.log 2>&1
	else
		python manage.py runserver 0.0.0.0:$PORT
	fi
fi
