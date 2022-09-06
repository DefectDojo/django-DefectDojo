#!/usr/bin/env bash

unset PROFILE
unset TEST_CASE

bash ./docker/docker-compose-check.sh
if [[ $? -eq 1 ]]; then exit 1; fi

usage() {
  echo
  echo "This script helps with running unit tests."
  echo
  echo "Options:"
  echo "  --profile -p {DOCKER_PROFILE_NAME}"
  echo "  --test-case -t {YOUR_FULLY_QUALIFIED_TEST_CASE}"
  echo
  echo "  --help -h - prints this dialogue."
  echo
  echo "Environment Variables:"
  echo "  DD_PROFILE={DOCKER_PROFILE_NAME}"
  echo
  echo "You must specify a test case (arg) and profile (arg or env var)!"
  echo
  echo "Example command:"
  echo "./dc-unittest.sh --profile mysql-rabbitmq --test-case unittests.tools.test_stackhawk_parser.TestStackHawkParser"
}

while [[ $# -gt 0 ]]; do
  case $1 in
    -p|--profile)
      PROFILE="$2"
      shift # past argument
      shift # past value
      ;;
    -t|--test-case)
      TEST_CASE="$2"
      shift # past argument
      shift # past value
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*|--*)
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

if [ -z $PROFILE ]
then
  if [ -z $DD_PROFILE ]
  then
    echo "No profile supplied."
    usage
    exit 1
  else
    PROFILE=$DD_PROFILE
  fi
fi

if [ -z $TEST_CASE ]
then
  echo "No test case supplied."
  usage
  exit 1
fi

echo "Running docker compose unit tests with profile $PROFILE and test case $TEST_CASE ..."
docker-compose --profile $PROFILE --env-file ./docker/environments/$PROFILE.env exec uwsgi bash -c "python manage.py test $TEST_CASE -v2"
