# Bash Client for APIv2
This files can be used in a continuous delivery/integration pipeline.

## Description
The `report-upload.bash` uploads a given report.
The cleanup file removes engagements, which does not have a corresponding branch.

## Usage
Modify _scan_type_ in `report-upload.bash` to the scan_type you want to use.

Create a product and fetch the Product ID.

Call ```
./report-upload.bash $PRODUCT_ID $BRANCH_NAME ./report-to-upload.xml
```

In case you are using feature branches and you want to upload reports for theses branches, you might want to remove not existing branches/engagements as following:
```
BRANCHES_TO_KEEP=$(git branch -a | sed 's#remotes/origin/##g' | sed 's# ##g' | tr '\n' ' ')
./clean-branches.bash 1 "dep check " "$BRANCHES_TO_KEEP"
```
