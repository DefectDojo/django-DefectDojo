#!/bin/bash

source ${BASH_SOURCE%/*}/../common-functions.bash
source ${BASH_SOURCE%/*}/../common-vars.bash


function check_pr_targets {
    : # Do nothing
}


function check_code_base_quality {
    # flake8-diff compares current branch to the equivalent of 'origin/master'
    # -> https://flake8-diff.readthedocs.io/en/latest/usage.html#controlling-comparisons
    git checkout "${TRAVIS_BRANCH}"

    #TODO: look for an alternative to flake8-diff, which  has open issues since
    #      2014, a draft-level documentation, and no code change since 2015.
    # -> https://github.com/dealertrack/flake8-diff/blob/master/flake8diff/main.py
}


function check_unwanted_changes {
    : # Do nothing
}


function check_sast {
    : # Do nothing
}


run_or_die check_"${CHECK}"
