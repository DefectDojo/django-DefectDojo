---
title: "Checkov Report"
toc_hide: true
---
### File Types
DefectDojo parser accepts Checkov scan data as a .JSON file.

JSON files can be created from the Checkov CLI: https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html

### Acceptable JSON Format

~~~
{
    "check_type": "terraform",
    "results": {
        "passed_checks": [
          ],
        "failed_checks": [
                {
                    "check_id": "CKV_AZURE_41",
                    "check_name": "Ensure the key vault is recoverable",
                    "check_result": {
                        "result": "FAILED"
                    },
                    "code_block": [
                    ],
                    "file_path": "file_path",
                    "file_line_range": [
                        1,
                        16
                    ],
                    "resource": "azurerm_key_vault.main",
                    "check_class": "checkov.terraform.checks.resource.azure.KeyvaultRecoveryEnabled",
                    "guideline": "https://docs.bridgecrew.io/docs/ensure-the-key-vault-is-recoverable"
                },
            ...
        ],
        "skipped_checks": [],
        "parsing_errors": []
    },
    "summary": {
        "passed": 0,
        "failed": 2,
        "skipped": 0,
        "parsing_errors": 0,
        "checkov_version": "1.0.467"
    }
}
~~~

### Sample Scan Data
Sample Checkov scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/checkov).