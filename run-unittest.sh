#!/usr/bin/env bash

unset TEST_CASE

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
  echo
  echo "Example command:"
  echo "./run-unittest.sh --test-case unittests.tools.test_stackhawk_parser.TestStackHawkParser"
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
    -*)
      echo "Unknown option $1"
      usage
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
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
# Compose V2 integrates compose functions into the Docker platform, continuing to support 
# most of the  previous docker-compose features and flags. You can run Compose V2 by 
# replacing the hyphen (-) with a space, using docker compose, instead of docker-compose.
docker compose exec uwsgi bash -c "python manage.py test $TEST_CASE -v2 --keepdb"
