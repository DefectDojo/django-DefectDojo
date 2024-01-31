---
title: "Talisman"
toc_hide: true
---
Run [Talisman](https://github.com/thoughtworks/talisman) in CLI mode and use "**--scan**" argument to scan the git commit history along with "**--reportDirectory**" argument to save the scan reports to a directory. The report will be in JSON format.

Additionally, you can set up Git Hooks to automate the scan and then send the generated reports to DefectDojo using its API.

Example:

```bash
#!/bin/sh

# Set DefectDojo API credential and other variables
DEFECTDOJO_API_KEY="your-api-key"
DEFECTDOJO_URL="https://your-defectdojo-url.com"
TALISMAN_RESULTS_DIR="$HOME"

# Run talisman in CLI mode and output the result in JSON format
CMD="talisman --scan --ignoreHistory --reportDirectory $TALISMAN_RESULTS_DIR"
$CMD

# Extract the result
result=$(jq '.results[].filename' "${TALISMAN_RESULTS_DIR}/talisman_reports/data/report.json")

# Check if result is not empty
if [ -n "$result" ]; then
  # If talisman found issues, send the JSON output to DefectDojo API endpoint
  curl -X POST \
    -H "Authorization: Token $DEFECTDOJO_API_KEY" \
    -H "Content-Type: application/json" \
    -d "@$TALISMAN_RESULTS_DIR/talisman_reports/data/report.json" \
    "$DEFECTDOJO_URL/api/v2/import-scan/"

  # Exit with a non-zero status code to indicate that the commit should be rejected
  exit 1
else
  # If talisman did not find any issues, exit with a zero status code
  exit 0
fi
```

### Sample Scan Data
Sample Talisman scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/talisman).