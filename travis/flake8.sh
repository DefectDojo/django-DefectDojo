#!/bin/bash

echo "$TRAVIS_BRANCH"
if [ "$TRAVIS_BRANCH" == "dev" ]
then
    echo "Running Flake8 tests on dev branch aka pull requests"
    # We need to checkout dev for flake8-diff to work properly
    git checkout dev
    pip install pep8 flake8 flake8-diff
    flake8-diff
else
    echo "true"
fi
