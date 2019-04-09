#!/bin/bash

# This shell script is used in combination with a tool run.
# A tool configured on DefectDojo using the ssh:// protocol can run this on the same or a remote server.

# This specific script is intended to demonstrate that functionality for the practical purpose of a vulnerability scanner.
# Make sure to configure a tool to parse result as the correct scanner and assign it to a product.

# You need to mark at least one endpoint manually to allow it to be provided as parameter to the target script.
# If you mark multiple endpoints, each will run in a separate thread.
# Endpoints are simply appended to the shell call (e.g. "/directory/arachni.bash http://example.com"), so inside a bash shell it will be available at $1.

# If the script controls a scanner and you want to parse the result, make sure to only output the correct code, as stdout is parsed.
# Scripts don't need to be parsed, so feel free to add debug statements and run it without parser.


# Step 1: Get the current directory
# This should be the same level of an extracted Arachni installation, next to the README
SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

# Step 2: Generate unique filename
# As the page could contain characters that are invalid filenames, we simply hash the URL by using a local openssl installation
PAGEID=$(echo -n "$1" | openssl dgst -sha256 | sed 's/^.* //')
if [ ! -f $SCRIPTPATH/scans/afr/$PAGEID.afr ]; then
    # Step 3: Run the scanner
    # If the file does not exist, run the scanner
    # This means that past results are cached - useful for testing, not good in a real scenario
    # Make sure that this output is suppressed (>/dev/null), otherwise the report would be corrupted with console output
    $SCRIPTPATH/bin/arachni $1 --report-save-path=$SCRIPTPATH/scans/afr/$PAGEID.afr >/dev/null
fi

# Step 4: Format output
# Arachni by default outputs it in a proprietary format.
# This is why we need to convert it to a JSON (and suppress the output as well).
$SCRIPTPATH/bin/arachni_reporter $SCRIPTPATH/scans/afr/$PAGEID.afr --reporter=json:outfile=$SCRIPTPATH/scans/json/$PAGEID.json >/dev/null

# Step 5: Output JSON
# Now that we have the scan result in a readable format, we give it to stdout, so that it can be parsed.
cat $SCRIPTPATH/scans/json/$PAGEID.json
