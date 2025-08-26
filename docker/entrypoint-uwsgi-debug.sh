#!/bin/bash

set -e  # needed to handle "exit" correctly

. /secret-file-loader.sh
. /reach_database.sh

wait_for_database_to_be_reachable
echo

cd /app || exit

echo "Debug mode enabled with debugpy support"
echo "Debugpy server will listen on 0.0.0.0:5678"
echo "Connect your VS Code debugger to localhost:5678"
echo "Application will start after debugger connects..."

# Start Django development server with debugpy
# --wait-for-client ensures the server waits for debugger connection
python -m debugpy --listen 0.0.0.0:5678 --wait-for-client manage.py runserver 0.0.0.0:8000