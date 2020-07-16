#!/bin/sh

echo "Waiting 60s for services to start"
# Wait for services to become available
sleep 60
echo "Testing DefectDojo Service"
curl -s -o "/dev/null" $DD_BASE_URL -m 120
CR=$(curl -s -m 10 -I "${DD_BASE_URL}login?next=/" | egrep "^HTTP" | cut  -d' ' -f2)
if [ "$CR" != 200 ]; then
    echo "ERROR: cannot display login screen; got HTTP code $CR"
    exit 1
fi

# Run available unittests with a simple setup
echo "Running Product type integration tests"
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

test="Product type integration tests"
echo "Running: $test"
if python3 tests/Product_type_unit_test.py ; then
    echo "Success: Product type integration tests passed"
else
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

# all smoke tests are already covered by other testcases above/below
# test="Smoke integration test"
# echo "Running: $test"
# if python3 tests/smoke_test.py ; then
#     success $test
# else
#     fail $test
# fi

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
