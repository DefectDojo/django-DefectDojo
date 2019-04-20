#!/bin/bash

DEFECT_DOJO_HOST_NAME="localhost"
API_KEY="CHANGE_ME"

PRODUCT_ID=$1
NAME_PREFIX=$2
BRANCHES_TO_KEEP=$3

API_URI="/api/v2"
DEFECTDOJO_HOST_URL="https://$DEFECT_DOJO_HOST_NAME$API_URI"

if [ "$PRODUCT_ID" == "" ]; then
	echo "Parameter PRODUCT_NAME not set";
	exit 1;
fi
if [ "$NAME_PREFIX" == "" ]; then
        echo "Parameter NAME_PREFIX not set";
        exit 1;
fi
if [ "$BRANCHES_TO_KEEP" == "" ]; then
        echo "Parameter BRANCH_NAME not set";
        exit 1;
fi

function is_int() { 
	printf "%f" $1 >/dev/null 2>&1
}
if [ $(echo $API_KEY | wc --chars) -ne 41 ]; then
	echo "Could not get API Key (got $(echo $API_KEY | wc --chars), expect 41 chars)"
	exit 3
fi
ENGAGEMENTS=$(curl --insecure --silent -X GET --header 'Accept: application/json' --header 'X-CSRFToken: X' --header "Authorization: Token $API_KEY" "$DEFECTDOJO_HOST_URL/engagements/?product=$PRODUCT_ID")
DD_RANDOM=$RANDOM
echo $ENGAGEMENTS | jq '.results[].name' | sed "s#$NAME_PREFIX##" | sed 's#/#-#g' | sort | uniq | sed 's/"//g' > existing-branches.txt
echo $BRANCHES_TO_KEEP | sed "s#$NAME_PREFIX##" | sed -e 's/\s\s*/\n/g' | sed 's#/#-#g' | sort > branches-to-keep.txt

diff --new-line-format="%L"  --old-line-format="" --unchanged-line-format="" branches-to-keep.txt existing-branches.txt > engagements-to-delete.txt

# delete engagements with no branch
while read BRANCH ; do
	if [ 0 -eq $(grep $BRANCH branches-to-keep.txt | wc -l) ]; then # delete engagement
      ENGAGEMENT_ID=$(echo $ENGAGEMENTS | jq ".results[]? | select(.branch_tag == \"$BRANCH\") | .id")
      echo "Deleting engagement/branch with id \"$ENGAGEMENT_ID\" (\"$BRANCH\")"
      RESP=$(curl --silent --insecure -X DELETE --header 'Accept: application/json' --header 'X-CSRFToken: X' --header "Authorization: Token $API_KEY" "$DEFECTDOJO_HOST_URL/engagements/$ENGAGEMENT_ID/?id=$ENGAGEMENT_ID")    
    fi
done < engagements-to-delete.txt
