---
title: "CodeQL"
toc_hide: true
---
Import CodeQL results in SARIF format, using the dedicated **CodeQL Scan** scan type. CodeQL is
GitHub's semantic code analysis engine: it builds a relational database from a codebase and runs
queries against it, so a result carries the whole data flow that reaches the problem rather than
just the offending line.

Generate a report with:

```shell
codeql database create db --language=<language> --source-root=.
codeql database analyze db --format=sarifv2.1.0 --sarif-add-snippets --output=results.sarif
```

The same can be achieved by running the CodeQL GitHub action with the `add-snippet` property set
to true.

Each result becomes one Finding, titled with the query id and the query's short description (for
example `py/sql-injection: SQL query built from user-controlled sources`). The query id leads
because a CodeQL result message describes the data flow that was found and is the same text for
every finding a given query raises, so it does not identify the query on its own.

For path queries, the reported data flow is written into the Finding description step by step, so
the source of the tainted value and the route it took to the sink are both visible without
returning to the scanner. The query's `precision` and `kind`, and the raw security severity
score, are recorded there too.

CodeQL SARIF can also still be imported with the generic **SARIF** scan type, which is how it
was handled before this parser existed. The CodeQL scan type is preferred: it titles findings by
query id and takes severity from CodeQL's own security severity score.

### Severity Mapping
CodeQL attaches a `security-severity` property to its security queries: a CVSS-style score out of
10, the same value GitHub code scanning uses to bucket alerts. DefectDojo maps that score through
its standard CVSS bands:

| CodeQL `security-severity` | DefectDojo severity |
| --- | --- |
| 9.0 and above | Critical |
| 7.0 to 8.9 | High |
| 4.0 to 6.9 | Medium |
| above 0, below 4.0 | Low |
| 0 | Info |

Queries that are not security queries carry no `security-severity`. For those the SARIF `level`
on the result, or the rule's default configuration, is used instead: `error` becomes High,
`warning` becomes Medium and `note` becomes Info. Nothing is defaulted to Medium unless CodeQL
reported neither a score nor a level.

CWE values come from the queries' own `external/cwe/cwe-NNN` tags, so a Finding is only given a
CWE that CodeQL asserted.

### Sample Scan Data
Sample CodeQL scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/codeql).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- file_path
- line
