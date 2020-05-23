set DD_ADMIN_USER=admin
set DD_ADMIN_PASSWORD=admin
set DD_BASE_URL=http://localhost:8080/

echo "Running Product type integration tests"
python tests/Product_type_unit_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Product integration tests"
python tests/Product_unit_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Endpoint integration tests"
python tests/Endpoint_unit_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Engagement integration tests"
python tests/Engagement_unit_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Environment integration tests"
python tests/Environment_unit_test.py 
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Finding integration tests"
python tests/Finding_unit_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Test integration tests"
python tests/Test_unit_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running User integration tests"
python tests/User_unit_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Ibm Appscan integration test"
python tests/ibm_appscan_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

everything in the smoke test is already covered by the other tests
echo "Running Smoke integration test"
python tests/smoke_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Check Status test"
python tests/check_status.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Dedupe integration tests"
python tests/dedupe_unit_test.py
if %ERRORLEVEL% NEQ 0 GOTO END



REM REM  The below tests are commented out because they are still an unstable work in progress
REM REM Once Ready they can be uncommented.

REM REM echo "Running Import Scanner integration test"
REM REM python tests/Import_scanner_unit_test.py
REM REM     echo "Success: Import Scanner integration tests passed" 
REM REM else
REM REM     echo "Error: Import Scanner integration test failed"; exit 1
REM REM fi

REM REM echo "Running Check Status UI integration test"
REM REM python tests/check_status_ui.py
REM REM     echo "Success: Check Status UI tests passed"
REM REM else
REM REM     echo "Error: Check Status UI test failed"; exit 1
REM REM fi

REM REM echo "Running Zap integration test"
REM REM python tests/zap.py
REM REM     echo "Success: zap integration tests passed"
REM REM else
REM REM     echo "Error: Zap integration test failed"; exit 1
REM REM fi

REM echo "Done Running all configured integration tests."

:END
