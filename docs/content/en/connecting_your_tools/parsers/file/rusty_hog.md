---
title: "Rusty Hog parser"
toc_hide: true
---
From: <https://github.com/newrelic/rusty-hog> Import the JSON output.
Rusty Hog is a secret scanner built in Rust for performance, and based on TruffleHog which is written in Python.

DefectDojo currently supports the parsing of the following Rusty Hog JSON outputs:
- Choctaw Hog: Scans for secrets in a Git repository.
- Duroc Hog: Scans for secrets in directories, files, and archives.
- Gottingen Hog: Scans for secrets in a JIRA issue.
- Essex Hog: Scans for secrets in a Confluence page.

RustyHog scans only one target at a time. This is not efficient if you want to scan all targets (e.g. all JIRA tickets) and upload each single report to DefectDojo.
[Rusty-Hog-Wrapper](https://github.com/manuel-sommer/Rusty-Hog-Wrapper) deals with this and scans a whole JIRA Project or Confluence Space, merges the findings into a valid file which can be uploaded to DefectDojo. (This is no official recommendation from DefectDojo, but rather a pointer in a direction on how to use this vulnerability scanner in a more efficient way.)

You can either select "Rusty Hog Scan" directly, or specify the sub scanner (e.g. "Duroc Hog Scan"). If you choose "Rusty Hog Scan", we recommend to re-import scans into the same test. For more information look at [this issue](https://github.com/DefectDojo/django-DefectDojo/issues/10584).

### Sample Scan Data
Sample Rusty Hog parser scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/rusty_hog).