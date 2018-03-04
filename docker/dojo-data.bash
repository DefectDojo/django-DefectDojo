#!/bin/bash
#Exports and loads sample data for dojo

# Set the paths
source ./entrypoint_scripts/common/dojo-build-env.sh

if [ $# > 1 ]
then
    if [[ "$1" = "load" ]]
    then
      python $DOJO_ROOT_DIR/manage.py loaddata $DOJO_DOCKER_DIR/sample_data/initial_dojo_data.json
      echo "Data imported from: sample_data/initial_dojo_data.json"
    elif [[ "$1" = "export" ]]; then
      python $DOJO_ROOT_DIR/manage.py dumpdata --exclude auth.user > $DOJO_DOCKER_DIR/sample_data/initial_dojo_data.json
      echo "Data exported to: sample_data/initial_dojo_data.json"
    fi
else
  echo "Pass in load for loading sample data in DefectDojo, or dump to export DefectDojo data."
fi
