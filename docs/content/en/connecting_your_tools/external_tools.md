---
title: "Universal Importer / Dojo-CLI"
description: "Import files to DefectDojo from the command line"
draft: false
weight: 2
---

## About Universal Importer

Universal Importer and Dojo-CLI are command-line tools designed to seamlessly upload scan results into DefectDojo. It streamlines both the import and re-import processes of findings and associated objects. These tools are flexible and supports importing and re-importing scan results, making it ideal for users who need robust interaction with the DefectDojo API.

Dojo-CLI has the same functionality as Universal Importer but also includes the ability to export Findings from DefectDojo to JSON or CSV.


## Installation
1. Use the DefectDojo UI to download the appropriate binary for your operating system from the platform.

2. Locate “External Tools” from your User Profile menu:

![image](images/external-tools.png)

3. Extract the downloaded archive within a directory of your choice.
Optional: Add the directory containing the extracted binary to your system's $PATH for repeat access.

**Note that Macintosh users may be blocked from running Dojo-CLI or Universal Importer as they are apps from an unidentified developer.  See [Apple Support](https://support.apple.com/en-ca/guide/mac-help/mh40616/mac) for instructions on how to override the block from Apple.**  

## Configuration
The Universal Importer can be configured using flags, environment variables, or a configuration file. The most important configuration is the API token, which must be set as an environment variable:

1. Add your API key to your environment variables. 
You can retrieve your API key from: `https://YOUR_INSTANCE.cloud.defectdojo.com/api/key-v2`

or 

Via the DefectDojo user interface 
in the user dropdown in the top-right corner:

![image](images/api-token.png)

2. Set your environment variable for the API token.
	`export DD_IMPORTER_DOJO_API_TOKEN=YOUR_API_KEY`

Note: On Windows, use `set` instead of `export`.

## Command Line Options
The following options can be used when calling the Universal Importer.

### Common Options (applicable to all commands):

```
--verbose
Enable verbose output for more detailed logging. (default: false)
--no-emojis, --no-emoji
Disable emojis in the output. (default: false)
--no-color
Disable color output. (default: false)
--help, -h
Show help information for the command.
--version, -v
Print the version of the Universal Importer.
```

## Usage: Import / Reimport
The Universal Importer supports two main commands: import and reimport.  Dojo-CLI supports those two commands, and also supports export.

### Import Command
Use the import command to import new findings into DefectDojo.

**Import Basic syntax:**
```
universal-importer import [options]
```

**Import Example:**
```
universal-importer import \
  --defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
  --scan-type "burp scan" \
  --report-path "./examples/burp_findings.xml" \
  --product-name "dev" \
  --engagement-name "dev" \
  --product-type-name "Research and Development" \
  --test-name "burp-test-dev" \
  --verified \
  --active \
  --minimum-severity "info" \
  --tag "dev" --tag "tools" --tag "burp" --tag "test-dev" \
  --test-version "0.0.1" \
  --auto-create-context
```

### Reimport Command
Use the `reimport` command to extend an existing Test with Findings from a new report.

**Reimport Basic syntax:**
`universal-importer reimport [options]`

**Reimport Example:**
```
universal-importer reimport \
  --defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
  --scan-type "Nancy Scan" \
  --report-path "./examples/nancy_findings.json" \
  --test-id 11 \
  --verified \
  --active \
  --minimum-severity "info" \
  --tag "dev" --tag "tools" --tag "nancy" --tag "test-dev" \
  --test-version "1.0" \
  --auto-create-context
```
### Import/Reimport Options
The following are the command parameters, definition, and supported environment variables for the Import function.

```
--defectdojo-url value, -u value
The URL of the DefectDojo instance to import findings into.
$DD_IMPORTER_DEFECTDOJO_URL
--report-path value, -r value
The path to the report to import. 
$DD_IMPORTER_REPORT_PATH
--scan-type value, -s value
The scan type of the tool. 
$DD_IMPORTER_SCAN_TYPE
--product-type-name value, --pt value: 
The name of the Product Type to import findings into. 
$DD_IMPORTER_PRODUCT_TYPE_NAME
--product-name value, -p value 
The name of the Product to import findings into. 
$DD_IMPORTER_PRODUCT_NAME
--engagement-name value, -e value
The name of the Engagement to import findings into. 
$DD_IMPORTER_ENGAGEMENT_NAME
--test-name value, --tn value
The name of the Test to import findings into - Defaults to the name of the scan type. 
$DD_IMPORTER_TEST_NAME
--active, -a 
Dictates whether findings should be active on import. (default: true) 
$DD_IMPORTER_ACTIVE
--minimum-severity value, --ms value
Dictates the lowest level severity that should be imported. 
Valid values are: Critical, High, Medium, Low, Info. (default: "Info") 
$DD_IMPORTER_MINIMUM_SEVERITY
--tag value, -t value
Any tags to be applied to the Test object (can be used multiple times) 
$DD_IMPORTER_TAGS
--verified, -v
Dictates whether findings should be verified on import. (default: false) $DD_IMPORTER_VERIFIED
--test-version value, -V value
The version of the test. 
$DD_IMPORTER_TEST_VERSION
--api-scan-configuration value, --asc value
The ID of the API Scan Configuration object to use when importing or reimporting (default: 0) 
$DD_IMPORTER_API_SCAN_CONFIGURATION
--auto-create-context, --acc 
If true, the importer automatically creates Engagements, Products, and Product_Types (default: false) 
$DD_IMPORTER_AUTO_CREATE_CONTEXT
--config value, -c value 
The path to the configuration file. 
$DD_IMPORTER_CONFIG_FILE
--engagement-id value, --ei value
The ID of the Engagement to import findings into. (default: 0) 
$DD_IMPORTER_ENGAGEMENT_ID
Reimport Specific - Reimport can create new tests or update an existing test of the same scan / scope.
--test-id value, --ti value
The ID of the Test to reimport findings into. (default: 0) 
$DD_IMPORTER_TEST_ID
```

## Usage: Export Command
Note that this command is only available with Dojo-CLI.

To export Findings from Dojo-CLI, you will need to supply a configuration file which contains details explaining which Findings you wish to export.  This is similar to the GET Findings method via the API.

For assistance use `defectdojo-cli export --help`.

#### Export Example:
```
defectdojo-cli export \
	--defectdojo-url "https://your-dojo-instance.cloud.defectdojo.com/"
```

### Set Output Destination

Specify one or both of these options depending on the export format you want to use:

```
	--csv "./path/to/findings.csv" \
	--json "./path/to/findings.json"
```
Note that Dojo-CLI will attempt to create a .csv or .json file if one does not exist already - your directory will need **write permissions** in order to do this.

You can also create the file in advance with `touch findings.csv`, for example.

### Filter Findings for Export

These flags are all optional and can be used to filter out a specific list of Findings to be included in the export file.  You can use any or all of these flags.
```
	--active "true" \
	--created "Past 90 days" \
	--cvssv3-score 0.0 \
	--cwe 589 \
	--date "Past 7 days" \
	--discovered-on "2019-01-01" \
	--discovered-after "2019-01-01" \
	--discovered-before "2019-01-01" \
	--duplicate "false" \
	--epss-percentile 0.0 \
	--epss-score 0.0 \
	--false-positive "false" \
	--is-mitigated "false" \
	--mitigated "Today" \
	--mitigated-on "2019-01-01" \
	--mitigated-after "2019-01-01" \
	--mitigated-before "2019-01-01" \
	--mitigated-by-ids 1 \
	--mitigated-by-ids 2 \
	--mitigated-by-ids 3 \
	--mitigated-by-names "user1" \
	--mitigated-by-names "user2" \
	--mitigated-by-names "user3" \
	--not-tags "tag1" \
	--not-tags "tag2" \
	--not-tags "tag3" \
	--tags "tag4" \
	--tags "tag5" \
	--tags "tag6" \
	--out-of-scope "false" \
	--out-of-sla "false" \
	--product-name-contains "dev" \
	--risk-accepted "false" \
	--severity "info" \
	--test-id 1 \
	--engagement "engagement_name" \
	--product-name "product_name" \
	--product-type-ids 1 \
	--product-type-ids 2 \
	--product-type-ids 3 \
	--product-type-names "product_type1" \
	--product-type-names "product_type2" \
	--product-type-names "product_type3" \
	--title-contains "title" \
	--under-review "false" \
	--verified "false" \
	--vulnerability-id 1
```

**Complete Example**
This example specifies the URL, export format and a few filter parameters to create a list of Findings.

```
defectdojo-cli export \
  --defectdojo-url "https://your-dojo-instance.cloud.defectdojo.com/"
  --json "./path/to/findings.json" \
  --active "true" \
  --created "Past 90 days"
```

## Troubleshooting
If you encounter any issues, please check the following:
- Ensure you're using the correct binary for your operating system and CPU architecture.
- Verify that the API key is set correctly in your environment variables.
- Check that the DefectDojo URL is correct and accessible.
- When importing, confirm that the report file exists and is in the supported format for the specified scan type.  You can review the supported scanners for Defect Dojo in the documentation https://documentation.defectdojo.com/integrations/parsers/file/. 

