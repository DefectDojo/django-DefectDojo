#!/bin/bash
#set -e
#set -x
#set -v

# generate "json" array of test cases to run

test_cases="["
for f in ../tests/*_test.py; do
#  echo "Processing $f file..."
  test_case_name=\"`basename $f .py`\"
  test_cases+=$test_case_name,
#  echo until now: ${test_cases[@]}
done

test_cases=`echo $test_cases | sed 's/.$//'`
test_cases+="]"
echo $test_cases
#echo ${test_cases[@]}

# echo $test_cases | jq -c '.[]'

# bash can't handle string with an array inside
tests=`echo $test_cases | sed 's/,/ /' | sed 's/\[//' |  sed 's/\]//'`
for t in $(echo $test_cases | jq -r -c '.[]'); do
  python "$t".py
done
