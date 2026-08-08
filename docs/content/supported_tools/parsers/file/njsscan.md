---
title: "njsscan"
toc_hide: true
---

[njsscan](https://github.com/ajinabraham/njsscan) is a static analyser for Node.js applications from the
MobSF authors. It looks for insecure code patterns in JavaScript and in the templates a framework
renders — OS command injection, `eval` on request data, reflected XSS, weak hashes — using Semgrep
patterns under the hood.

### Field mapping

| njsscan | DefectDojo |
|---|---|
| rule id (the key, e.g. `node_md5`) | `title`, `vuln_id_from_tool` |
| `metadata.severity` (`ERROR` / `WARNING` / `INFO`) | `severity` (High / Medium / Low) |
| `metadata.cwe` | `cwe` (the integer, parsed out of the sentence) |
| `metadata.description`, `metadata.owasp-web` | `description` |
| `files[].file_path` | `file_path` |
| `files[].match_lines[0]` | `line` |
| `files[].match_string` | snippet in `description` |

njsscan groups its output **by rule**, with a list of matches under each, and splits those groups into
a `nodejs` section and a `templates` section. Every match becomes its own finding, so a rule that
matches three places yields three findings — counting rules would undercount. The section a finding came
from is recorded in the description.

The CWE arrives as a whole sentence rather than a number — `"CWE-327: Use of a Broken or Risky
Cryptographic Algorithm"` — so the integer is extracted for the `cwe` field and the full text is kept in
the description.

A match spanning several lines reports `match_lines` as a `[start, end]` pair. The finding anchors to the
start line and the description keeps the range.

### Sample Scan Data

Sample njsscan files are available at
[unittests/scans/njsscan](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/njsscan).

### Generating an importable file

```bash
pip install njsscan
njsscan --json -o njsscan.json <path-to-source>
```

**Check your Python version.** On Python 3.12 njsscan reports **zero findings and exits successfully**,
with an empty `errors` array and nothing on stderr. The cause is its Semgrep dependency, which still
imports `pkg_resources`; that module was removed from the default install in 3.12, so the scanning engine
fails to load and njsscan reports an empty result rather than an error. Run it on Python 3.11, or install
`setuptools` alongside it. A clean report from njsscan is worth verifying against a file you know
should fail.

The fixtures committed with this parser were produced with **njsscan 0.4.3 on Python 3.11** by three
separate runs against the JavaScript files committed alongside them in `unittests/scans/njsscan/`:

| Fixture | Findings |
|---|---|
| `njsscan_no_vuln.json` | 0 — `safe.js` |
| `njsscan_one_vuln.json` | 1 — `hash.js`, a weak hash |
| `njsscan_many_vuln.json` | 5 — `server.js`, four rules of which one matches twice |

njsscan's rules are deliberately taint-aware: `child_process.exec` on a plain function argument does not
fire, while the same call on `req.query.dir` does. A fixture that means to trigger the injection rules
has to route request data into them.

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — the legacy default, which is the same key the
Semgrep parser uses and the right one for a rule at a source position.
