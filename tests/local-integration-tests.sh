#!/bin/bash

export DD_BASE_URL='http://localhost:8080/'


# All available Unittest Scripts are activated below
# If successful, A success message is printed and the script continues
# If any script is unsuccessful a failure message is printed and the test script
# Exits with status code of 1


echo "Running Product type integration tests"
if python3 tests/Regulations_unit_test.py ; then
    echo "Success: Regulation integration tests passed"
else
    docker-compose logs uwsgi --tail=120
    echo "Error: Regulation integration test failed."; exit 1
fi


echo "Running Product type integration tests"
if python3 tests/Product_type_unit_test.py ; then
    echo "Success: Product type integration tests passed"
else
    docker-compose logs uwsgi --tail=120
    echo "Error: Product type integration test failed."; exit 1
fi

echo "Running Product integration tests"
if python3 tests/Product_unit_test.py ; then 
    echo "Success: Product integration tests passed"
else
    docker-compose logs uwsgi --tail=120
    echo "Error: Product integration test failed"; exit 1
fi

echo "Running Dedupe integration tests"
if python3 tests/dedupe_unit_test.py ; then
    echo "Success: Dedupe integration tests passed"
else
    docker-compose logs uwsgi --tail=120
    echo "Error: Dedupe integration test failed"; exit 1
fi

echo "Running Endpoint integration tests"
if python3 tests/Endpoint_unit_test.py ; then
    echo "Success: Endpoint integration tests passed"
else
    docker-compose logs uwsgi --tail=120
    echo "Error: Endpoint integration test failed"; exit 1
fi

echo "Running Engagement integration tests"
if python3 tests/Engagement_unit_test.py ; then
    echo "Success: Engagement integration tests passed"
else
    docker-compose logs uwsgi --tail=120
    echo "Error: Engagement integration test failed"; exit 1
fi

echo "Running Environment integration tests"
if python3 tests/Environment_unit_test.py ; then 
    echo "Success: Environment integration tests passed"
else
    docker-compose logs uwsgi --tail=120
    echo "Error: Environment integration test failed"; exit 1
fi

echo "Running Finding integration tests"
if python3 tests/Finding_unit_test.py ; then
    echo "Success: Finding integration tests passed"
else
    docker-compose logs uwsgi --tail=120
    echo "Error: Finding integration test failed"; exit 1
fi

echo "Running Test integration tests"
if python3 tests/Test_unit_test.py ; then
    echo "Success: Test integration tests passed"
else
    docker-compose logs uwsgi --tail=120
    echo "Error: Test integration test failed"; exit 1
fi

echo "Running User integration tests"
if python3 tests/User_unit_test.py ; then
    echo "Success: User integration tests passed"
else
    docker-compose logs uwsgi --tail=120
    echo "Error: User integration test failed"; exit 1
fi

echo "Running Ibm Appscan integration test"
if python3 tests/ibm_appscan_test.py ; then
    echo "Success: Ibm AppScan integration tests passed"
else
    docker-compose logs uwsgi --tail=120
    echo "Error: Ibm AppScan integration test failed"; exit 1
fi

# everything in the smoke test is already covered by the other tests
# echo "Running Smoke integration test"
# if python3 tests/smoke_test.py ; then
#     echo "Success: Smoke integration tests passed"
# else
#     docker-compose logs uwsgi --tail=120
#     echo "Error: Smoke integration test failed"; exit 1
# fi

echo "Running Check Status test"
if python3 tests/check_status.py ; then
    echo "Success: check status tests passed"
else
    docker-compose logs uwsgi --tail=120
    echo "Error: Check status tests failed"; exit 1
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
