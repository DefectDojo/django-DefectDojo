set DD_ADMIN_USER=admin
set DD_ADMIN_PASSWORD=admin
set DD_BASE_URL=http://localhost:8080/

echo "Running Product type integration tests"
python tests/product_type_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Product integration tests"
python tests/product_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Endpoint integration tests"
python tests/endpoint_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Engagement integration tests"
python tests/engagement_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Environment integration tests"
python tests/environment_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Finding integration tests"
python tests/finding_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Test integration tests"
python tests/test_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running User integration tests"
python tests/user_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Ibm Appscan integration test"
python tests/ibm_appscan_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Search integration test"
python tests/search_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Dedupe integration tests"
python tests/dedupe_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Report Builder integration tests"
python tests/report_builder_test.py
if %ERRORLEVEL% NEQ 0 GOTO END

echo "Running Check Various Pages integration test"
python tests/check_various_pages.py
if %ERRORLEVEL% NEQ 0 GOTO END

REM REM  The below tests are commented out because they are still an unstable work in progress
REM REM Once Ready they can be uncommented.

REM REM echo "Running Import Scanner integration test"
rem rem python tests/import_scanner_test.py
REM REM     echo "Success: Import Scanner integration tests passed"
REM REM else
REM REM     echo "Error: Import Scanner integration test failed"; exit 1
REM REM fi

REM REM echo "Running Zap integration test"
REM REM python tests/zap.py
REM REM     echo "Success: zap integration tests passed"
REM REM else
REM REM     echo "Error: Zap integration test failed"; exit 1
REM REM fi

REM echo "Done Running all configured integration tests."

:END
