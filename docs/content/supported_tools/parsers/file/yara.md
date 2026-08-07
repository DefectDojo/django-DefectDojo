---
title: "YARA"
toc_hide: true
---

Import the output of [YARA](https://virustotal.github.io/yara/), which matches files against
detection rules.

### File Types

Plain text, as printed by `yara`. Two flags decide how much a finding can say, and both are worth
using:

```
yara -r -s -m rules.yar /path/to/scan > yara.txt
```

- **`-m`** prints the rule's metadata, which is where a severity lives if the ruleset records one.
- **`-s`** prints the offset and text of each matched string, which becomes the evidence in the
  finding. Note that this is content copied out of the scanned file.

Plain `yara rules.yar target` prints only the rule name and the path, and that parses too — the
findings just have less in them.

One finding is created per rule-and-file pair. A rule that matches the same file several times is one
finding with every matched offset listed, not one finding per offset. The rule name becomes
`vuln_id_from_tool` and the scanned path becomes `file_path`.

**Severity comes from the rule.** A YARA rule fires because someone wrote it to fire, but what the
match *means* is entirely up to the rule, and YARA itself has no notion of severity. A `severity`
value in the rule's metadata is used (`critical`, `high`, `medium`/`moderate`, `low`,
`info`/`informational`); anything else — including a rule with no metadata at all — gets **Medium**.

A run where nothing matches prints nothing and still exits 0, so an empty file parses to zero
findings.

Metadata is read with a parser rather than by splitting on commas, because a value can contain one:
`yara -m` prints all metadata as a single bracketed list, escapes quotes inside string values, and
prints an integer value as `key =90` — with a space before the `=` but not after.

### Sample Scan Data

Sample YARA scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/yara).

The rules that produced them are in `rules.yar` next to the captures; they match placeholder strings
in local sample files, so nothing here depends on a real detection ruleset.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file_path
- description
