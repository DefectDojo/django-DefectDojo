#!/bin/bash
# called from entrypoint-initializer.sh when no admin user exists (first boot)
cat <<EOD | python manage.py shell
import os
from django.contrib.auth.models import User
User.objects.create_superuser(
  os.getenv('DD_ADMIN_USER'),
  os.getenv('DD_ADMIN_MAIL'),
  os.getenv('DD_ADMIN_PASSWORD'),
  first_name=os.getenv('DD_ADMIN_FIRST_NAME'),
  last_name=os.getenv('DD_ADMIN_LAST_NAME')
)
EOD

  # load surveys all at once as that's much faster
   echo "Importing fixtures all at once"
   python3 manage.py loaddata system_settings initial_banner_conf product_type test_type \
       development_environment benchmark_type benchmark_category benchmark_requirement \
       language_type objects_review regulation initial_surveys role sla_configurations

  echo "UPDATE dojo_system_settings SET jira_webhook_secret='$DD_JIRA_WEBHOOK_SECRET'" | python manage.py dbshell

  echo "Importing extra fixtures"
  # If there is extra fixtures, load them
  for i in $(find dojo/fixtures/extra_*.json | sort -n 2>/dev/null) ; do
    echo "Loading $i"
    python3 manage.py loaddata "${i%.*}"
  done

  echo "Installing watson search index"
  python3 manage.py installwatson

  # surveys fixture needs to be modified as it contains an instance dependant polymorphic content id
  echo "Migration of textquestions for surveys"
  python3 manage.py migrate_textquestions