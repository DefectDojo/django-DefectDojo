#!/usr/bin/env bash
unset TEST_CASE
EXTRA_ARGS=()

bash ./docker/docker-compose-check.sh
if [[ $? -eq 1 ]]; then exit 1; fi

usage() {
  echo
  echo "This script helps with running unit tests."
  echo
  echo "Options:"
  echo "  --test-case -t {YOUR_FULLY_QUALIFIED_TEST_CASE}"
  echo "  --help -h - prints this dialogue."
  echo
  echo "You must specify a test case (arg)!"
  echo "Any additional arguments will be passed to the test command."
  echo
  echo "Example commands:"
  echo "./run-unittest.sh --test-case unittests.tools.test_stackhawk_parser.TestStackHawkParser"
  echo "./run-unittest.sh --test-case unittests.tools.test_stackhawk_parser.TestStackHawkParser -v3 --failfast"
}

while [[ $# -gt 0 ]]; do
  case $1 in
    -t|--test-case)
      TEST_CASE="$2"
      shift # past argument
      shift # past value
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      EXTRA_ARGS+=("$1") # save extra arg
      shift # past argument
      ;;
  esac
done

if [ -z "$TEST_CASE" ]
then
  echo "No test case supplied."
  usage
  exit 1
fi

echo "Running docker compose unit tests with test case $TEST_CASE ..."
if [ ${#EXTRA_ARGS[@]} -gt 0 ]; then
  echo "Additional arguments: ${EXTRA_ARGS[*]}"
fi

docker compose exec uwsgi bash -c "python manage.py test $TEST_CASE -v2 ${EXTRA_ARGS[*]} --keepdb"
