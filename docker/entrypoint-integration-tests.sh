#!/bin/bash

echo "Waiting 60s for services to start"
# Wait for services to become available
sleep 60
echo "Testing DefectDojo Service"
curl -s -o "/dev/null" $DD_BASE_URL -m 120
CR=$(curl --insecure -s -m 10 -I "${DD_BASE_URL}login?next=/" | egrep "^HTTP" | cut  -d' ' -f2)
if [ "$CR" != 200 ]; then
    echo "ERROR: cannot display login screen; got HTTP code $CR"
    exit 1
fi

# Run available unittests with a simple setup
# All available Integrationtest Scripts are activated below
# If successsful, A successs message is printed and the script continues
# If any script is unsuccesssful a failure message is printed and the test script
# Exits with status code of 1

function fail() {
    echo "Error: $1 test failed\n"
    exit 1
}

function success() {
    echo "Success: $1 test passed\n"
}

test="Notes integration tests"
echo "Running: $test"
if python3 tests/Notes_unit_test.py ; then
    success $test
else
    fail $test
fi

test="Regulation integration tests"
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

test="User integration tests"
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

# all smoke tests are already covered by other testcases above/below
# test="Smoke integration test"
# echo "Running: $test"
# if python3 tests/smoke_test.py ; then
#     success $test
# else
#     fail $test
# fi

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

exec echo "Done Running all configured integration tests."
