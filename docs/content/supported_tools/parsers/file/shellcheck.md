---
title: "ShellCheck"
toc_hide: true
---
Import ShellCheck reports in JSON format. ShellCheck is a static analyser for shell scripts.

Generate a report with:

```
shellcheck -f json script.sh > shellcheck.json
```

### Scope
ShellCheck is a general linter rather than a dedicated security scanner, but several of its
checks are security relevant — `SC2086` (unquoted expansion allowing word splitting and
globbing), `SC2115` (`rm -rf $VAR/*` expanding to `/*` when the variable is empty) and unsafe
`eval` use among them. Results are imported with ShellCheck's own levels preserved so
stylistic results can be filtered after import.

### Severity Mapping
| ShellCheck level | DefectDojo severity |
| --- | --- |
| error | High |
| warning | Medium |
| info | Low |
| style | Info |

ShellCheck reports its check id as a bare integer; it is rendered in the documented `SCnnnn`
form and linked to the corresponding wiki page. Checks that ShellCheck can rewrite
automatically are marked as having a fix available.

### Sample Scan Data
Sample ShellCheck scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/shellcheck).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- file_path
- line
