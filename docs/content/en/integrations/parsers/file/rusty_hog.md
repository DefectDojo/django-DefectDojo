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
