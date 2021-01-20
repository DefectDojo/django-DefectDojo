#!/bin/sh
# Run available unittests with a setup for local dev:
# - Make migrations and apply any needed changes
# - Leave container up after running tests to allow debugging, rerunning tests, etc.
set -x
set -e
set -v

cd /app
# Unset the database URL so that we can force the DD_TEST_DATABASE_NAME (see django "DATABASES" configuration in settings.dist.py)
unset DD_DATABASE_URL

python3 manage.py makemigrations dojo
python3 manage.py migrate

echo "Swagger Schema Tests - Broken"
echo "------------------------------------------------------------"
python3 manage.py test dojo.unittests -v 3 --no-input --tag broken && true

echo "Unit Tests"
echo "------------------------------------------------------------"
python3 manage.py test dojo.unittests -v 3 --no-input --exclude-tag broken

# you can select a single file to "test" unit tests 
# python3 manage.py test dojo.unittests.test_npm_audit_scan_parser.TestNpmAuditParser --keepdb -v 3

# or even a single method
# python3 manage.py test dojo.unittests.test_npm_audit_scan_parser.TestNpmAuditParser.test_npm_audit_parser_many_vuln_npm7 --keepdb -v 3

echo "End of tests. Leaving the container up"
tail -f /dev/null
