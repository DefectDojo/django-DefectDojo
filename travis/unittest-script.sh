#!/bin/bash

umask 0002

echo "Waiting for services to start"
docker-compose up -d
# wait for images to build and services to become available
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

echo "Running Product type unit tests"
if python3 tests/Product_type_unit_test.py ; then
    echo "Success: Product type unit tests passed"
else
    echo "Error: Product type unittest failed."; exit 1
fi

echo "Running Product unit tests"
if python3 tests/Product_unit_test.py ; then 
    echo "Success: Product unit tests passed"
else
    echo "Error: Product unit tests failed"; exit 1
fi

echo "Running Endpoint unit tests"
if python3 tests/Endpoint_unit_test.py ; then
    echo "Success: Endpoint unit tests passed"
else
    echo "Error: Endpoint unit tests failed"; exit 1
fi

echo "Running Engagement unit tests"
if python3 tests/Engagement_unit_test.py ; then
    echo "Success: Engagement unit tests passed"
else
    echo "Error: Engagement unittest failed"; exit 1
fi

echo "Running Environment unit tests"
if python3 tests/Environment_unit_test.py ; then 
    echo "Success: Environment unit tests passed"
else
    echo "Error: Environment unittest failed"; exit 1
fi

echo "Running Finding unit tests"
if python3 tests/Finding_unit_test.py ; then
    echo "Success: Finding unit tests passed"
else
    echo "Error: Finding unittest failed"; exit 1
fi

echo "Running Test unit tests"
if python3 tests/Test_unit_test.py ; then
    echo "Success: Test unit tests passed"
else
    echo "Error: Test unittest failed"; exit 1
fi

echo "Running User unit tests"
if python3 tests/User_unit_test.py ; then
    echo "Success: User unit tests passed"
else
    echo "Error: User unittest failed"; exit 1
fi

echo "Running Ibm Appscan unit test"
if python3 tests/ibm_appscan_test.py ; then
    echo "Success: Ibm AppScan unit tests passed"
else
    echo "Error: Ibm AppScan unittest failed"; exit 1
fi

echo "Running Smoke unit test"
if python3 tests/smoke_test.py ; then
    echo "Success: Smoke unit tests passed"
else
    echo "Error: Smoke unittest failed"; exit 1
fi

echo "Running Check Status test"
if python3 tests/check_status.py ; then
    echo "Success: check status tests passed"
else
    echo "Error: Check status tests failed"; exit 1
fi

# echo "Running Dedupe unit tests"
# if python3 tests/dedupe_unit_test.py ; then
#     echo "Success: Dedupe unit tests passed"
# else
#     echo "Error: Dedupe unittest failed"; exit 1
# fi

# The below tests are commented out because they are still an unstable work in progress
## Once Ready they can be uncommented.

# echo "Running Import Scanner unit test"
# if python3 tests/Import_scanner_unit_test.py ; then
#     echo "Success: Import Scanner unit tests passed" 
# else
#     echo "Error: Import Scanner unit tests failed"; exit 1
# fi

# echo "Running Check Status UI unit test"
# if python3 tests/check_status_ui.py ; then
#     echo "Success: Check Status UI unit tests passed"
# else
#     echo "Error: Check Status UI test failed"; exit 1
# fi

# echo "Running Zap unit test"
# if python3 tests/zap.py ; then
#     echo "Success: zap unit tests passed"
# else
#     echo "Error: Zap unittest failed"; exit 1
# fi

exec echo "Done Running all configured unittests."
