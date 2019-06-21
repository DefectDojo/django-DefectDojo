#!/bin/bash
# upgrade.bash helps you upgrading DefectDojo in your current environment
#
#

printf "\n\n==============================================================================\n"
printf "DefectDojo Upgrade Script.\n\n"
printf "RECOMMENDATION:\n"
printf "Before upgrading please stop your DefectDojo and Celery prcoesses.\n"
printf "==============================================================================\n\n"

# Initialize variables and functions
source entrypoint_scripts/common/dojo-shared-resources.sh

# This function invocation ensures we're running the script at the right place
verify_cwd

function prompt_env() {
  read -p "Is there a virtual environment for DefectDojo? (Default is yes): (y/n): " ENVSETUP
  ENVSETUP=${ENVSETUP:-y}
  if [ "$ENVSETUP" == "y" ] \
      || [ "$ENVSETUP" == "n" ] ; then
      printf "\n"
  else
      printf "Please enter y or n\n\n"
      prompt_env
  fi
}

prompt_env

function prompt_env_name() {
  read -p "What is the name of the virtual environment? (Default is venv): " ENVNAME
  ENVNAME=${ENVNAME:-'venv'}
  if [ -z "$ENVNAME" ] ;  then
      prompt_env_name
  fi
}

if [ "$ENVSETUP" == "y" ] ; then
  prompt_env_name
  source $ENVNAME/bin/activate
fi

printf "\n==============================================================================\n"
printf "Backing up database using django-dbbackup.\n"
printf "For more information please visit:\n"
printf "https://github.com/django-dbbackup/django-dbbackup\n"
printf "==============================================================================\n\n"

#Check to see if django dbbackup is installed
BACKUP="$(pip list | grep -F django-dbbackup)"
if [ -z "$BACKUP" ] ;  then
  printf "Installing django-dbbackup...."
  pip install django-dbbackup
fi

function prompt_db_loc() {
  read -p "Please provide a directory path to backup the DefectDojo database: " DBPATH
  if [ -z "$DBPATH" ] ;  then
      prompt_db_loc
  elif [ ! -d "$DBPATH" ]; then
    printf "Path provided does not exist.\n"
    prompt_db_loc
  fi
  printf "\n"
}

#Prompt for the location to backup the database file to
prompt_db_loc

#Generate the filename
CURR_DATE=$(date "+%Y.%m.%d-%H.%M.%S")
DB_BACKUP_NAME="django-db-$CURR_DATE.dump.gz"
length=${#DBPATH}
last_char=${DBPATH:length-1:1}

[[ $last_char != "/" ]] && DBPATH="$DBPATH/";
#Backup the database compressed
python manage.py dbbackup --output-path $DBPATH$DB_BACKUP_NAME --compress

printf "\n==============================================================================\n"
printf "Pulling the latest version from master.\n"
printf "==============================================================================\n\n"
git checkout master
git pull

printf "==============================================================================\n"
printf "Upgrading the pip installs.\n"
printf "==============================================================================\n\n"
pip install -r requirements.txt --upgrade

printf "==============================================================================\n"
printf "Upgrading static components.\n"
printf "==============================================================================\n\n"
cd components
yarn
cd ..
./manage.py collectstatic --noinput

printf "==============================================================================\n"
printf "Upgrading the database.\n"
printf "==============================================================================\n\n"
./manage.py makemigrations
./manage.py migrate

printf "==============================================================================\n"
printf "Upgrade complete!\n"
printf "==============================================================================\n\n"
