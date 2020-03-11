#!/bin/bash

umask 0002

echo "Waiting for services to start"
docker-compose up -d
# wait for containers to start from images and services to become available
sleep 100 # giving long enough time

## Installing Google Chrome browser
sudo apt-get install -y gdebi && \
    wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb && \
    sudo gdebi google-chrome-stable_current_amd64.deb -n

## Installing Chromium Driver and Selenium for test automation
LATEST_VERSION=$(curl -s https://chromedriver.storage.googleapis.com/LATEST_RELEASE) && \
    wget -O /tmp/chromedriver.zip https://chromedriver.storage.googleapis.com/$LATEST_VERSION/chromedriver_linux64.zip && \
    sudo unzip /tmp/chromedriver.zip chromedriver -d /usr/local/bin/ && \
    sudo chmod 777 /usr/local/bin/chromedriver;

python3 -m pip install selenium requests --user || exit 1 

# Exporting Username and password to env for access by automation scripts
CONTAINER_NAME=django-defectdojo_initializer_1
echo "export DD_ADMIN_USER=admin" >> ~/.profile && \
    container_id=(`docker ps -a --filter name=${CONTAINER_NAME}.* | awk 'FNR == 2 {print $1}'`) && \
    docker logs $container_id 2>&1 | grep "Admin password:"| cut -c17- | (read passwordss; echo "export DD_ADMIN_PASSWORD=$passwordss" >> ~/.profile) && \
    source ~/.profile

# All available Unittest Scripts are activated below
# If successful, A success message is printed and the script continues
# If any script is unsuccessful a failure message is printed and the test script
# Exits with status code of 1

export DD_BASE_URL='http://localhost:8080/'

echo "Running Product type integration tests"
if python3 tests/Product_type_unit_test.py ; then
    echo "Success: Product type integration tests passed"
else
    docker-compose logs --tail="all" uwsgi
    echo "Error: Product type integration test failed."; exit 1
fi

echo "Running Product integration tests"
if python3 tests/Product_unit_test.py ; then 
    echo "Success: Product integration tests passed"
else
    echo "Error: Product integration test failed"; exit 1
fi

echo "Running Endpoint integration tests"
if python3 tests/Endpoint_unit_test.py ; then
    echo "Success: Endpoint integration tests passed"
else
    echo "Error: Endpoint integration test failed"; exit 1
fi

echo "Running Engagement integration tests"
if python3 tests/Engagement_unit_test.py ; then
    echo "Success: Engagement integration tests passed"
else
    echo "Error: Engagement integration test failed"; exit 1
fi

echo "Running Environment integration tests"
if python3 tests/Environment_unit_test.py ; then 
    echo "Success: Environment integration tests passed"
else
    echo "Error: Environment integration test failed"; exit 1
fi

echo "Running Finding integration tests"
if python3 tests/Finding_unit_test.py ; then
    echo "Success: Finding integration tests passed"
else
    echo "Error: Finding integration test failed"; exit 1
fi

echo "Running Test integration tests"
if python3 tests/Test_unit_test.py ; then
    echo "Success: Test integration tests passed"
else
    echo "Error: Test integration test failed"; exit 1
fi

echo "Running User integration tests"
if python3 tests/User_unit_test.py ; then
    echo "Success: User integration tests passed"
else
    echo "Error: User integration test failed"; exit 1
fi

echo "Running Ibm Appscan integration test"
if python3 tests/ibm_appscan_test.py ; then
    echo "Success: Ibm AppScan integration tests passed"
else
    echo "Error: Ibm AppScan integration test failed"; exit 1
fi

echo "Running Smoke integration test"
if python3 tests/smoke_test.py ; then
    echo "Success: Smoke integration tests passed"
else
    echo "Error: Smoke integration test failed"; exit 1
fi

echo "Running Check Status test"
if python3 tests/check_status.py ; then
    echo "Success: check status tests passed"
else
    echo "Error: Check status tests failed"; exit 1
fi

echo "Running Dedupe integration tests"
if python3 tests/dedupe_unit_test.py ; then
    echo "Success: Dedupe integration tests passed"
else
    echo "Error: Dedupe integration test failed"; exit 1
fi

# The below tests are commented out because they are still an unstable work in progress
## Once Ready they can be uncommented.

# echo "Running Import Scanner integration test"
# if python3 tests/Import_scanner_unit_test.py ; then
#     echo "Success: Import Scanner integration tests passed" 
# else
#     echo "Error: Import Scanner integration test failed"; exit 1
# fi

# echo "Running Check Status UI integration test"
# if python3 tests/check_status_ui.py ; then
#     echo "Success: Check Status UI tests passed"
# else
#     echo "Error: Check Status UI test failed"; exit 1
# fi

# echo "Running Zap integration test"
# if python3 tests/zap.py ; then
#     echo "Success: zap integration tests passed"
# else
#     echo "Error: Zap integration test failed"; exit 1
# fi

exec echo "Done Running all configured integration tests."
