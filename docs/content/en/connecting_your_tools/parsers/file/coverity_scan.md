---
title: "Coverity Scan JSON Report"
toc_hide: true
---
### File Types
This DefectDojo parser accepts JSON files created from the [Synopsys Coverity CLI](https://www.synopsys.com/software-integrity/static-analysis-tools-sast/coverity.html) using the following command: `coverity scan`.

Documentation for CLI can be found [here](https://sig-product-docs.synopsys.com/bundle/coverity-docs/page/cli/topics/using_the_coverity_cli.html).

### Example Commands to retrieve JSON output
Run `coverity scan --project-dir <project_dir> --local <result_file> --local-format json` to create the JSON report.

### Sample Scan Data
Sample Coverity scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/coverity_scan).