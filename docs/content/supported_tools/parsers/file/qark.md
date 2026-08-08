---
title: "QARK"
toc_hide: true
---

[QARK](https://github.com/linkedin/qark) (Quick Android Review Kit) is LinkedIn's static analyser for
Android applications. It decompiles an APK and checks both the manifest and the recovered code for
common Android weaknesses — exported components without permissions, TapJacking exposure, logging left
in a release build, hard-coded keys.

### Field mapping

| QARK | DefectDojo |
|---|---|
| `name` (e.g. `Exported tags`) | `title`, `vuln_id_from_tool` |
| `severity` (`VULNERABILITY` / `WARNING` / `INFO`) | `severity` (High / Medium / Info) |
| `description`, `category`, `apk_exploit_dict` | `description` |
| `file_object`, with the build path stripped | `file_path` |
| `line_number[0]` | `line` |

`line_number` is a `[line, column]` pair, and manifest-level issues omit it entirely along with
`file_object` — TapJacking, for instance, is a property of the whole application and reports neither.

**Build paths are stripped.** `file_object` is an absolute path through whatever build directory the run
used, e.g. `/tmp/build/qark/cfr/com/example/App.java`. Everything up to and including QARK's own
`/qark/` output marker is removed, leaving `cfr/com/example/App.java` — readable, and stable between runs
that used different build directories. A path without that marker is reported verbatim.

### Two behaviours to expect

**Code issues are reported twice.** QARK decompiles with *both* fernflower and cfr, and scans both
outputs, so a single log call surfaces as two findings under paths differing only by the decompiler
name. The two log calls in the sample application produce four `Logging found` findings. They are
imported faithfully rather than merged: the line numbers genuinely differ between the two decompilers'
output, so there is no single correct location to merge them to. Filter on the path prefix if you want
one decompiler's view.

**The signing block trips the API-key check.** QARK scans `META-INF/*.RSA`, and the random bytes of an
APK signature can match its API-key pattern. `qark_one_vuln.json` is exactly that false positive. It is
not deterministic — re-signing the same application may or may not reproduce it.

Also worth knowing: the JSON writer logs `Error converting issue <enum 'Activity'> to JSON` on some
runs and omits the affected issues, so a JSON report can be missing findings that the HTML report
shows. That is a QARK defect, not a parsing problem.

### Sample Scan Data

Sample QARK files are available at
[unittests/scans/qark](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/qark).

### Generating an importable file

```bash
pip install qark
qark --apk app.apk --report-type json
```

Two practical notes:

* QARK needs a **JDK**, not just a JRE — it calls `jar` while unpacking, and with a JRE only it fails
  with `FileNotFoundError: 'jar'` partway through and still writes a report.
* The report is written **inside QARK's own package directory**
  (`<site-packages>/qark/report/report.json`), not into `--build-path`. Collect it from there.

The fixtures committed with this parser were produced with **QARK 4.0.0** against the same small Android
application used for the APKLeaks fixtures, whose sources are committed under
`unittests/scans/apkleaks/`:

| Fixture | Findings |
|---|---|
| `qark_no_vuln.json` | 0 — `minSdkVersion 21`, activity not exported, no logging |
| `qark_one_vuln.json` | 1 — the signing-block false positive |
| `qark_many_vuln.json` | 6 — exported activity, TapJacking, and four `Logging found` |

A zero-finding scan needs care: without a `minSdkVersion` of 9 or higher QARK always reports TapJacking,
and an exported activity always reports `Exported tags`.

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — the legacy default. QARK reports no CWE, so
findings are distinguished by name, location and description.
