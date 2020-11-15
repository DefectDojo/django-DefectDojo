#!/bin/bash

umask 0002

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
    container_id=(`docker ps -a --filter name=${CONTAINER_NAME}.* | awk 'FNR ==2 {print $1}'`) && \
    docker logs $container_id 2>&1 | grep "Admin password:"| cut -c17- | (read passwordss; echo "export DD_ADMIN_PASSWORD=$passwordss" >> ~/.profile) && \
    source ~/.profile

# All available Unittest Scripts are activated below
# If successsful, A successs message is printed and the script continues
# If any script is unsuccesssful a failure message is printed and the test script
# Exits with status code of 1

export DD_BASE_URL='http://localhost:8080/'

test_failures=false
function fail() {
    echo "Error: $1 test failed\n"
    docker-compose logs --tail="120" uwsgi
    test_failures=true
}

function success() {
    echo "Grepping celery logs for errors:"
    docker-compose logs --tail="all" celeryworker | grep -A 12 " ERROR" && mark_failed_celery
    echo "Success: $1 test passed\n"
}

celery_failures=false
function mark_failed_celery() {
    # can be used to mark the build as failed, but still continue to see what the rest of the test suite does
    celery_failures=true
}

test="Running Product type integration tests"
echo "Running: $test"
if python3 tests/Regulations_unit_test.py ; then
    success $test
else
    fail $test
fi

test="Product type integration tests"
echo "Running: $test"
if python3 tests/Product_type_unit_test.py ; then
    success $test
else
    fail $test
fi

test="Product integration tests"
echo "Running: $test"
if python3 tests/Product_unit_test.py ; then 
    success $test
else
    fail $test
fi

test="Notes integration tests"
echo "Running: $test"
if python3 tests/Notes_unit_test.py ; then
    success $test
else
    fail $test
fi

test="Endpoint integration tests"
echo "Running: $test"
if python3 tests/Endpoint_unit_test.py ; then
    success $test
else
    fail $test
fi

test="Engagement integration tests"
echo "Running: $test"
if python3 tests/Engagement_unit_test.py ; then
    success $test
else
    fail $test
fi

test="Environment integration tests"
echo "Running: $test"
if python3 tests/Environment_unit_test.py ; then 
    success $test
else
    fail $test
fi

test="Finding integration tests"
echo "Running: $test"
if python3 tests/Finding_unit_test.py ; then
    success $test
else
    fail $test
fi

test="Test integration tests"
echo "Running: $test"
if python3 tests/Test_unit_test.py ; then
    success $test
else
    fail $test
fi

test=echo "User integration tests"
echo "Running: $test"
if python3 tests/User_unit_test.py ; then
    success $test
else
    fail $test
fi

test="Ibm Appscan integration test"
echo "Running: $test"
if python3 tests/ibm_appscan_test.py ; then
    success $test
else
    fail $test
fi

test="Smoke integration test"
echo "Running: $test"
if python3 tests/smoke_test.py ; then
    success $test
else
    fail $test
fi

test="Check Status test"
echo "Running: $test"
if python3 tests/check_status.py ; then
    success $test
else
    fail $test
fi

test="Dedupe integration tests"
echo "Running: $test"
if python3 tests/dedupe_unit_test.py ; then
    success $test
else
    fail $test
fi



# The below tests are commented out because they are still an unstable work in progress
## Once Ready they can be uncommented.

# echo "Import Scanner integration test"
# if python3 tests/Import_scanner_unit_test.py ; then
#     echo "Success: Import Scanner integration tests passed" 
# else
#     echo "Error: Import Scanner integration test failed"; exit 1
# fi

# echo "Check Status UI integration test"
# if python3 tests/check_status_ui.py ; then
#     echo "Success: Check Status UI tests passed"
# else
#     echo "Error: Check Status UI test failed"; exit 1
# fi

# echo "Zap integration test"
# if python3 tests/zap.py ; then
#     echo "Success: zap integration tests passed"
# else
#     echo "Error: Zap integration test failed"; exit 1
# fi

if [ $test_failures = true ] ; then
    echo "some tests have failed, see logs above"
    exit 1
fi

if [ $celery_failures = true ] ; then
    echo "there ERRORs found in the celery worker logs, see above"
    exit 1
fi

exec echo "Done Running all configured integration tests."
