#!/bin/bash
#Exports and loads sample data for dojo

if [ $# > 1 ]
then
    if [[ "$1" = "load" ]]
    then
      python /django-DefectDojo/manage.py loaddata /django-DefectDojo/docker/sample_data/initial_dojo_data.json
      echo "Data imported from: sample_data/initial_dojo_data.json"
    elif [[ "$1" = "export" ]]; then
      python /django-DefectDojo/manage.py dumpdata --exclude auth.user > /django-DefectDojo/docker/sample_data/initial_dojo_data.json
      echo "Data exported to: sample_data/initial_dojo_data.json"
    fi
else
  echo "Pass in load for loading sample data in DefectDojo, or dump to export DefectDojo data."
fi
