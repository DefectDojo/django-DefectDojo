---
title: "Datadog dd-trace IAST JSON"
toc_hide: true
---

Import the IAST (Interactive Application Security Testing) vulnerabilities that the open-source
Datadog tracing libraries ([dd-trace](https://github.com/DataDog/dd-trace-py)) detect by taint
tracking inside a running application.

This is **not** the [Datadog Cloud Security](/supported_tools/parsers/file/datadog/) parser. That one imports findings Datadog's
SaaS has already processed; this one reads what the tracer itself emits, so it works for a tracer
that sends its traces to your own collector and never to Datadog.

### File Types

JSON: an array of span records.

With `DD_IAST_ENABLED=true` a tracer writes no report file. Each span that reached a vulnerable sink
with tainted data carries an IAST report in its `meta_struct["iast"]` field (msgpack-encoded, on the
tracer's `/v0.4/traces` intake). The importable file is one record per such span, holding that report
decoded to JSON under `iast` next to the span's own fields:

```json
[
  {
    "service": "shop",
    "env": "qa",
    "resource": "GET /items",
    "trace_id": "6859907763198533562",
    "span_id": "13170496397258556481",
    "start": 1795433469096730763,
    "iast": {
      "vulnerabilities": [
        {
          "type": "SQL_INJECTION",
          "evidence": {"valueParts": [{"value": "select * from u where n='"}, {"redacted": true, "source": 0}, {"value": "'"}]},
          "location": {"path": "app.py", "line": 6, "method": "items", "spanId": 13170496397258556481},
          "hash": 651293933
        }
      ],
      "sources": [{"origin": "http.request.parameter", "name": "n", "redacted": true}]
    }
  }
]
```

Only `iast` is required in a record; the span fields are optional context. Any trace intake that
decodes `meta_struct` can produce the file, for example a small agent-compatible service, or the
OpenTelemetry Collector's Datadog receiver, which turns the same report into `iast.vulnerability`
span events.

A file that is not a JSON array, or a record without an `iast` object, is rejected with an error
instead of importing nothing.

### Fields

Per span record:

1. **service** - component name; also half of the deduplication key.
2. **env** - added as a tag next to `ddtrace-iast`.
3. **resource** - shown in the description as the route.
4. **trace_id**, **span_id** - shown in the description, to find the request in a trace viewer.
5. **start** - span start in nanoseconds since the epoch; the finding date.
6. **iast.vulnerabilities** - one finding each, see below.
7. **iast.sources** - the taint sources; the description names each one a vulnerability's evidence
   points at, as `origin:name`.

Per vulnerability:

1. **type** - the title's first half; severity and CWE (table below).
2. **location.path**, **location.line** - file path and line; the title's second half.
3. **location.method** - shown in the description; the title falls back to it without a path.
4. **evidence** - rendered into the description from `valueParts` (or `value`). A part marked
   `redacted` is shown as `[redacted]`.
5. **hash** - `vuln_id_from_tool`. The tracer computes it from the type and the code location.
6. **location.spanId**, **location.stackId** - not parsed.

### Field Mapping Details

- **Severity and CWE.** The tracer reports no severity, so it is derived from the type:

  | Type | Severity | CWE |
  | --- | --- | --- |
  | `SQL_INJECTION` | High | 89 |
  | `COMMAND_INJECTION` | High | 78 |
  | `CODE_INJECTION` | High | 94 |
  | `HEADER_INJECTION` | High | 113 |
  | `PATH_TRAVERSAL` | High | 22 |
  | `SSRF` | High | 918 |
  | `XSS` | High | 79 |
  | `UNTRUSTED_DESERIALIZATION` | High | 502 |
  | `UNVALIDATED_REDIRECT` | Medium | 601 |
  | `WEAK_HASH` | Medium | 328 |
  | `WEAK_CIPHER` | Medium | 327 |
  | `WEAK_RANDOMNESS` | Medium | 330 |
  | `INSECURE_COOKIE` | Medium | 614 |
  | `NO_HTTPONLY_COOKIE` | Medium | 1004 |
  | `NO_SAMESITE_COOKIE` | Medium | 1275 |
  | `STACKTRACE_LEAK` | Low | 209 |
  | anything else | Info | none |

- **Redaction is kept.** The tracer redacts evidence that looks sensitive. A redacted part is never
  rendered from any other field, and a source contributes only its origin and name, never its value.
- **Dynamic findings.** Every finding is `dynamic_finding`: the tracer saw it happen on a live request.
- **Occurrences.** The same bug hit by many requests carries the same hash. Within one file, records
  with the same service and hash become one finding, and `nb_occurences` counts them.

### Sample Scan Data

Sample dd-trace IAST scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/ddtrace_iast).

The samples are decoded from real dd-trace-py 4.17.2 trace payloads (a path traversal, a command
injection and a SQL injection on a demo Flask app). `many_vulns.json` adds a second request and a
second service hitting the same SQL injection; `edge_cases.json` covers evidence without `valueParts`,
a source index out of range, an unknown type and a missing location.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- component_name
- vuln_id_from_tool

That is the service and the tracer's hash, so a re-import of the same bug does not create a new
finding, and two services sharing a file name and line stay apart.

### Link To Tool

- [dd-trace-py](https://github.com/DataDog/dd-trace-py) (other languages: dd-trace-java, dd-trace-js, dd-trace-dotnet)
- [Datadog Code Security (IAST) documentation](https://docs.datadoghq.com/security/code_security/iast/)
