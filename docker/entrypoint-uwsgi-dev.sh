#!/bin/sh

umask 0002

# Copy settings.py (settings.py copied to allow for legacy installs and customizations)
cd /app
TARGET_SETTINGS_FILE=dojo/settings/settings.py
if [ ! -f ${TARGET_SETTINGS_FILE} ]; then
  echo "Creating settings.py"
  cp dojo/settings/settings.dist.py dojo/settings/settings.py
fi

while ping -c1 initializer 1>/dev/null 2>/dev/null
  do {
    echo "Waiting for initializer to complete" 
    sleep 3
  }
  done; 
  echo "Starting DefectDojo: http://localhost:8000"
  
python manage.py runserver 0.0.0.0:8000