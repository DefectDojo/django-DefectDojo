#!/usr/bin/env bash

unset TEST_CASE

bash ./docker/docker-compose-check.sh
if [[ $? -eq 1 ]]; then exit 1; fi

usage() {
  echo
  echo "This script helps with running integration tests."
  echo
  echo "Options:"
  echo "  --test-case -t {YOUR_FULLY_QUALIFIED_TEST_CASE}"
  echo "  --help -h - prints this dialogue."
  echo
  echo
  echo "Example command:"
  echo './run-unittest.sh --test-case "Finding integration tests"'
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

echo "Running docker compose unit tests with profile postgres-redis and test case $TEST_CASE ..."

# Compose V2 integrates compose functions into the Docker platform,
# continuing to support most of the previous docker-compose features
# and flags. You can run Compose V2 by replacing the hyphen (-) with
# a space, using docker compose, instead of docker-compose.
echo "Building images..."
./docker/setEnv.sh integration_tests
docker compose build
echo "Setting up DefectDojo with Postgres and Redis..."
DD_INTEGRATION_TEST_FILENAME="$TEST_CASE" docker compose -d postgres nginx celerybeat celeryworker mailhog uwsgi redis
echo "Initializing DefectDojo..."
DD_INTEGRATION_TEST_FILENAME="$TEST_CASE" docker compose --exit-code-from initializer initializer
echo "Running the integration tests..."
DD_INTEGRATION_TEST_FILENAME="$TEST_CASE" docker compose --exit-code-from integration-tests integration-tests
