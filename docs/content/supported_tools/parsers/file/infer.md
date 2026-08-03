---
title: "Infer"
toc_hide: true
---

[Infer](https://fbinfer.com/) is Meta's interprocedural static analyser for C, C++, Objective-C and
Java. Rather than pattern-matching, it reasons about program state across function boundaries, which is
why its findings come with a trace explaining how the issue is reached — a null dereference reports where
the null came from, not just where it was dereferenced.

### Field mapping

| Infer | DefectDojo |
|---|---|
| `bug_type_hum` (e.g. `Null Dereference`) | `title` |
| `bug_type` (e.g. `NULLPTR_DEREFERENCE`) | `vuln_id_from_tool` |
| `severity` (`ERROR` / `WARNING` / `INFO` / `ADVICE`) | `severity` (High / Medium / Low / Info) |
| `qualifier`, `category`, `procedure`, `column` | `description` |
| `bug_trace[]` | `description` |
| `file` | `file_path` |
| `line` | `line` |

Infer reports no CWE, so findings carry none rather than a guessed value.

### Infer's `hash` is not a unique finding id

Each issue carries a `hash` (and a `key`, and a `node_key`), and it is tempting to use it as
`unique_id_from_tool`. **It is not unique per issue** — it identifies the *bug site*. Two distinct
results at the same line share a hash whenever the analyser reaches that line by more than one path: a
pointer that could be null both because it was initialised to `NULL` and because an allocation might
fail is reported twice, with one hash.

Deduplicating on it would silently discard one of two real findings, so it is recorded in the
description for traceability only. What differs between such issues is the `qualifier` and the trace,
both of which are in the description and therefore part of the `hash_code`.

### Sample Scan Data

Sample Infer files are available at
[unittests/scans/infer](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/infer).

### Generating an importable file

Infer wraps a build, so give it the command that compiles the project:

```bash
infer run -- gcc -c app.c          # or: make, mvn compile, gradle build, ...
```

The report to import is `infer-out/report.json`. `--results-dir <dir>` puts it somewhere else.

Note that Infer analyses what the build actually compiles. Running it against a source tree without a
working build command produces an empty report rather than an error.

The fixtures committed with this parser were produced with **Infer v1.3.0** by three separate runs
against the C files committed alongside them in `unittests/scans/infer/`:

| Fixture | Findings |
|---|---|
| `infer_no_vuln.json` | 0 — `safe.c` |
| `infer_one_vuln.json` | 1 — `deref.c`, a null dereference |
| `infer_many_vuln.json` | 9 — `defects.c`: memory leaks, null dereferences, a use after free, uninitialised reads |

Infer's official release binaries need **glibc 2.38 or newer**; on an older base image `infer` fails to
start and, depending on how it is invoked, that can look like a scan that simply found nothing.

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — the legacy default. The description carries the
qualifier and trace, which is what keeps two issues at one line distinct.
