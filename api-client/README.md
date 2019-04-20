# Bash Client for APIv2
This files can be used in a continuous delivery/integration pipeline.

## Description
The _report-upload.bash_ uploads a given report.
The _cleanup-branches.bash_ file removes engagements, which does not have a corresponding branch.

## Usage
Modify _scan_type_ in _report-upload.bash_ to the scan_type you want to use.
Modify the prefix in the POST (_name_) according to your needs. For example "dep check" to have the prefix dep check for engamgents using _OWASP Dependency Check_.

Create a product and fetch the Product ID.

Call 
```
./report-upload.bash $PRODUCT_ID $BRANCH_NAME ./report-to-upload.xml
```

In case you are using feature branches and you want to upload reports for theses branches, you might want to remove not existing branches/engagements as following:
```
BRANCHES_TO_KEEP=$(git branch -a | sed 's#remotes/origin/##g' | sed 's# ##g' | tr '\n' ' ')
./clean-branches.bash 1 "dep check " "$BRANCHES_TO_KEEP"
```
