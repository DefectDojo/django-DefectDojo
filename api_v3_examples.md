# DefectDojo API v3 (alpha) — worked examples

> **Auto-generated, do not hand-edit.** Every request/response below was captured by `unittests/api_v3/test_apiv3_examples.py` (`DD_API_V3_EXAMPLES=1`, CI-excluded) making **real** in-process requests against the test fixture. Tokens are redacted; long lists are truncated to ~3 rows. Regenerate with the command in that file's docstring.

Captured: 2026-07-21T17:33:30.749529+00:00

## Conventions (see `API_V3_PLAN.md` §4)

- **Mount:** alpha lives at `/api/v3-alpha/` (moves to `/api/v3/` at beta — one migration, D1). Every response carries `X-API-Status: alpha`.
- **Auth (D8):** send an existing v2 token as `Authorization: Token <key>` (works unchanged on v3), or a Django session cookie + `X-CSRFToken` on unsafe methods.
- **Envelope & pagination (§4.3):** every list is `{count, next, previous, results, meta?}` and nothing else (I1). `next`/`previous` are opaque URLs. Offset mode is the default (`limit=25`, max `250`); `?pagination=cursor` opts into forward-only keyset paging (`count`/`previous` null, opaque signed cursor in `next`).
- **Refs (§4.4):** relations render as `{id, name}` (locations add `type`). Write payloads reference relations by integer id — the asymmetry is intentional (§4.11).
- **Writes (§4.11):** `PATCH` is a partial update (only supplied fields change); `PUT` is a full replace (omitted optionals reset to their defaults). Both reject unknown fields (400).
- **CSV export (§4.15):** `GET /<resource>/export.csv` streams the whole filtered, authorized set as CSV using the identical filter/`o=`/`q=`/`fields=` contract (no pagination); refs flatten to `_id`/`_name` columns, list fields join with `;`.
- **`?expand=` (§4.6):** dotted paths swap refs for slim objects inline and drive the queryset (the real N+1 fix). Budget-guarded.
- **`?fields=` (§4.7):** comma-separated allowlist; `id` is always included. On a list it may also request any detail field (a wider SELECT on one query, never per-row).
- **`?include=counts` (§4.8):** adds aggregate totals to `meta` over the filtered, authorized queryset.
- **Errors (§4.10):** RFC 9457 `application/problem+json` with a `fields` extension for validation errors.

---
### Finding — GET detail (slim + detail fields)

Retrieve a single finding. Relations render as closed `{id, name}` refs (§4.4); the parent chain (`test`/`engagement`/`asset`/`organization`) is denormalized onto the finding. `locations_count` is an annotation; the full list is a sub-resource (§4.14).

**Request**

```http
GET /api/v3-alpha/findings/2
Authorization: Token <your-api-token>
```

**Response** — `200`

```json
{
  "id": 2,
  "title": "High Impact Test Finding",
  "severity": "High",
  "active": true,
  "verified": true,
  "false_p": false,
  "duplicate": false,
  "risk_accepted": false,
  "out_of_scope": false,
  "is_mitigated": false,
  "date": "2020-05-21",
  "cwe": 79,
  "cwes": [
    79,
    89
  ],
  "vulnerability_ids": [
    "CVE-2024-3094",
    "GHSA-8r3f-844x-mdgq"
  ],
  "test": {
    "id": 3,
    "name": "ZAP Scan"
  },
  "engagement": {
    "id": 1,
    "name": "1st Quarter Engagement"
  },
  "asset": {
    "id": 2,
    "name": "Security How-to"
  },
  "organization": {
    "id": 2,
    "name": "ebooks"
  },
  "reporter": {
    "id": 1,
    "name": "admin"
  },
  "locations_count": 3,
  "tags": [
    "internal",
    "tls"
  ],
  "created": "2017-12-01T00:00:00Z",
  "updated": "2026-07-21T17:33:29.998Z",
  "description": "test finding",
  "mitigation": "test mitigation",
  "impact": "Unauthorized disclosure of customer data if exploited.",
  "steps_to_reproduce": null,
  "severity_justification": null,
  "references": "",
  "file_path": "",
  "line": null,
  "mitigated": null,
  "mitigated_by": null
}
```


---

### Finding — GET detail with `?expand=test.engagement,locations`

`?expand=` swaps a ref for the target's slim object inline and drives real `select_related`/`prefetch_related` (§4.6). `expand=locations` replaces `locations_count` with edge rows `{location, status, audit_time, auditor}`.

**Request**

```http
GET /api/v3-alpha/findings/2?expand=test.engagement,locations
Authorization: Token <your-api-token>
```

**Response** — `200`

```json
{
  "id": 2,
  "title": "High Impact Test Finding",
  "severity": "High",
  "active": true,
  "verified": true,
  "false_p": false,
  "duplicate": false,
  "risk_accepted": false,
  "out_of_scope": false,
  "is_mitigated": false,
  "date": "2020-05-21",
  "cwe": 79,
  "cwes": [
    79,
    89
  ],
  "vulnerability_ids": [
    "CVE-2024-3094",
    "GHSA-8r3f-844x-mdgq"
  ],
  "test": {
    "id": 3,
    "name": null,
    "test_type": {
      "id": 1,
      "name": "ZAP Scan"
    },
    "engagement": {
      "id": 1,
      "name": "1st Quarter Engagement",
      "asset": {
        "id": 2,
        "name": "Security How-to"
      },
      "organization": {
        "id": 2,
        "name": "ebooks"
      },
      "lead": {
        "id": 2,
        "name": "user1"
      },
      "status": "In Progress",
      "engagement_type": "Interactive",
      "target_start": "2018-04-12",
      "target_end": "2018-04-12",
      "active": true,
      "tags": [],
      "created": null,
      "updated": null
    },
    "asset": {
      "id": 2,
      "name": "Security How-to"
    },
    "organization": {
      "id": 2,
      "name": "ebooks"
    },
    "environment": {
      "id": 1,
      "name": "Development"
    },
    "lead": null,
    "target_start": "2017-12-01T00:00:00Z",
    "target_end": "2017-12-10T00:00:00Z",
    "percent_complete": 100,
    "tags": [],
    "created": null,
    "updated": null
  },
  "engagement": {
    "id": 1,
    "name": "1st Quarter Engagement"
  },
  "asset": {
    "id": 2,
    "name": "Security How-to"
  },
  "organization": {
    "id": 2,
    "name": "ebooks"
  },
  "reporter": {
    "id": 1,
    "name": "admin"
  },
  "tags": [
    "internal",
    "tls"
  ],
  "created": "2017-12-01T00:00:00Z",
  "updated": "2026-07-21T17:33:29.998Z",
  "description": "test finding",
  "mitigation": "test mitigation",
  "impact": "Unauthorized disclosure of customer data if exploited.",
  "steps_to_reproduce": null,
  "severity_justification": null,
  "references": "",
  "file_path": "",
  "line": null,
  "mitigated": null,
  "mitigated_by": null,
  "locations": [
    {
      "location": {
        "id": 2,
        "name": "ftp://localhost",
        "type": "url"
      },
      "status": "Active",
      "audit_time": null,
      "auditor": null
    },
    {
      "location": {
        "id": 9,
        "name": "https://example.com/login",
        "type": "url"
      },
      "status": "Active",
      "audit_time": null,
      "auditor": null
    },
    {
      "location": {
        "id": 10,
        "name": "https://example.com/admin",
        "type": "url"
      },
      "status": "Mitigated",
      "audit_time": null,
      "auditor": null
    }
  ]
}
```


---

### Finding — GET list, filtered (`severity=High&active=true`) + pagination page 2

The filter grammar is a documented, snapshot-tested vocabulary (§4.9). The list envelope is always `{count, next, previous, results, meta?}` (I1); `next`/`previous` are opaque URLs (D4). Here `limit=2&offset=2` is page 2, so both are non-null.

**Request**

```http
GET /api/v3-alpha/findings?severity=High&active=true&limit=2&offset=2
Authorization: Token <your-api-token>
```

**Response** — `200`

```json
{
  "count": 8,
  "next": "http://testserver/api/v3-alpha/findings?severity=High&active=true&limit=2&offset=4",
  "previous": "http://testserver/api/v3-alpha/findings?severity=High&active=true&limit=2&offset=0",
  "results": [
    {
      "id": 234,
      "title": "example high active 0",
      "severity": "High",
      "active": true,
      "verified": true,
      "false_p": false,
      "duplicate": false,
      "risk_accepted": false,
      "out_of_scope": false,
      "is_mitigated": false,
      "date": "2026-07-21",
      "cwe": 0,
      "cwes": [],
      "vulnerability_ids": [],
      "test": {
        "id": 3,
        "name": "ZAP Scan"
      },
      "engagement": {
        "id": 1,
        "name": "1st Quarter Engagement"
      },
      "asset": {
        "id": 2,
        "name": "Security How-to"
      },
      "organization": {
        "id": 2,
        "name": "ebooks"
      },
      "reporter": {
        "id": 1,
        "name": "admin"
      },
      "locations_count": 0,
      "tags": [],
      "created": "2026-07-21T17:33:29.979Z",
      "updated": "2026-07-21T17:33:29.979Z"
    },
    {
      "id": 235,
      "title": "example high active 1",
      "severity": "High",
      "active": true,
      "verified": true,
      "false_p": false,
      "duplicate": false,
      "risk_accepted": false,
      "out_of_scope": false,
      "is_mitigated": false,
      "date": "2026-07-21",
      "cwe": 0,
      "cwes": [],
      "vulnerability_ids": [],
      "test": {
        "id": 3,
        "name": "ZAP Scan"
      },
      "engagement": {
        "id": 1,
        "name": "1st Quarter Engagement"
      },
      "asset": {
        "id": 2,
        "name": "Security How-to"
      },
      "organization": {
        "id": 2,
        "name": "ebooks"
      },
      "reporter": {
        "id": 1,
        "name": "admin"
      },
      "locations_count": 0,
      "tags": [],
      "created": "2026-07-21T17:33:29.979Z",
      "updated": "2026-07-21T17:33:29.979Z"
    }
  ]
}
```


---

### Finding — GET list, cursor pagination (`?pagination=cursor`) — page 1

Forward-only keyset mode for export/sync consumers (D4/§4.3). Same envelope, but `count` and `previous` are always `null` and `next` carries an opaque, signed `cursor=` token (truncated below). No `COUNT` query runs; the page is read as `limit+1` rows to detect a next page. Keyset-safe orderings only (`id` default, plus `created`/`updated` where a resource declares them); filters/`fields=`/`expand=`/`include=` compose unchanged.

**Request**

```http
GET /api/v3-alpha/findings?pagination=cursor&severity=High&active=true&limit=2
Authorization: Token <your-api-token>
```

**Response** — `200`

```json
{
  "count": null,
  "next": "http://testserver/api/v3-alpha/findings?pagination=cursor&severity=High&active=true&limit=2&cursor=eyJvIjoiaWQiLCJpZCI6...<cursor truncated>",
  "previous": null,
  "results": [
    {
      "id": 2,
      "title": "High Impact Test Finding",
      "severity": "High",
      "active": true,
      "verified": true,
      "false_p": false,
      "duplicate": false,
      "risk_accepted": false,
      "out_of_scope": false,
      "is_mitigated": false,
      "date": "2020-05-21",
      "cwe": 79,
      "cwes": [
        79,
        89
      ],
      "vulnerability_ids": [
        "CVE-2024-3094",
        "GHSA-8r3f-844x-mdgq"
      ],
      "test": {
        "id": 3,
        "name": "ZAP Scan"
      },
      "engagement": {
        "id": 1,
        "name": "1st Quarter Engagement"
      },
      "asset": {
        "id": 2,
        "name": "Security How-to"
      },
      "organization": {
        "id": 2,
        "name": "ebooks"
      },
      "reporter": {
        "id": 1,
        "name": "admin"
      },
      "locations_count": 3,
      "tags": [
        "internal",
        "tls"
      ],
      "created": "2017-12-01T00:00:00Z",
      "updated": "2026-07-21T17:33:29.998Z"
    },
    {
      "id": 232,
      "title": "Disabling CSRF Protections Is Security-Sensitive",
      "severity": "High",
      "active": true,
      "verified": true,
      "false_p": false,
      "duplicate": false,
      "risk_accepted": false,
      "out_of_scope": false,
      "is_mitigated": false,
      "date": "2025-10-22",
      "cwe": 352,
      "cwes": [],
      "vulnerability_ids": [],
      "test": {
        "id": 90,
        "name": "SonarQube Scan detailed"
      },
      "engagement": {
        "id": 5,
        "name": "April monthly engagement2"
      },
      "asset": {
        "id": 2,
        "name": "Security How-to"
      },
      "organization": {
        "id": 2,
        "name": "ebooks"
      },
      "reporter": {
        "id": 1,
        "name": "admin"
      },
      "locations_count": 0,
      "tags": [],
      "created": "2025-10-22T08:29:41.361Z",
      "updated": null
    }
  ]
}
```


---

### Finding — GET list, cursor pagination — page 2 (following `next`)

Follow the page-1 `next` URL verbatim (opaque). The signed cursor encodes only the ordering + last-row key position (never the filters), so the keyset predicate reads exactly the rows after that position — no offset, no count. When `next` is `null` the walk is complete.

**Request**

```http
GET /api/v3-alpha/findings?pagination=cursor&severity=High&active=true&limit=2&cursor=eyJvIjoiaWQiLCJpZCI6...<cursor truncated>
Authorization: Token <your-api-token>
```

**Response** — `200`

```json
{
  "count": null,
  "next": "http://testserver/api/v3-alpha/findings?pagination=cursor&severity=High&active=true&limit=2&cursor=eyJvIjoiaWQiLCJpZCI6...<cursor truncated>",
  "previous": null,
  "results": [
    {
      "id": 234,
      "title": "example high active 0",
      "severity": "High",
      "active": true,
      "verified": true,
      "false_p": false,
      "duplicate": false,
      "risk_accepted": false,
      "out_of_scope": false,
      "is_mitigated": false,
      "date": "2026-07-21",
      "cwe": 0,
      "cwes": [],
      "vulnerability_ids": [],
      "test": {
        "id": 3,
        "name": "ZAP Scan"
      },
      "engagement": {
        "id": 1,
        "name": "1st Quarter Engagement"
      },
      "asset": {
        "id": 2,
        "name": "Security How-to"
      },
      "organization": {
        "id": 2,
        "name": "ebooks"
      },
      "reporter": {
        "id": 1,
        "name": "admin"
      },
      "locations_count": 0,
      "tags": [],
      "created": "2026-07-21T17:33:29.979Z",
      "updated": "2026-07-21T17:33:29.979Z"
    },
    {
      "id": 235,
      "title": "example high active 1",
      "severity": "High",
      "active": true,
      "verified": true,
      "false_p": false,
      "duplicate": false,
      "risk_accepted": false,
      "out_of_scope": false,
      "is_mitigated": false,
      "date": "2026-07-21",
      "cwe": 0,
      "cwes": [],
      "vulnerability_ids": [],
      "test": {
        "id": 3,
        "name": "ZAP Scan"
      },
      "engagement": {
        "id": 1,
        "name": "1st Quarter Engagement"
      },
      "asset": {
        "id": 2,
        "name": "Security How-to"
      },
      "organization": {
        "id": 2,
        "name": "ebooks"
      },
      "reporter": {
        "id": 1,
        "name": "admin"
      },
      "locations_count": 0,
      "tags": [],
      "created": "2026-07-21T17:33:29.979Z",
      "updated": "2026-07-21T17:33:29.979Z"
    }
  ]
}
```


---

### Finding — GET list with `?include=counts`

`?include=counts` adds severity/status totals computed over the *filtered, authorized* queryset into `meta` in one aggregate query — no second round-trip (§4.8).

**Request**

```http
GET /api/v3-alpha/findings?include=counts&limit=2
Authorization: Token <your-api-token>
```

**Response** — `200`

```json
{
  "count": 27,
  "next": "http://testserver/api/v3-alpha/findings?include=counts&limit=2&offset=2",
  "previous": null,
  "results": [
    {
      "id": 2,
      "title": "High Impact Test Finding",
      "severity": "High",
      "active": true,
      "verified": true,
      "false_p": false,
      "duplicate": false,
      "risk_accepted": false,
      "out_of_scope": false,
      "is_mitigated": false,
      "date": "2020-05-21",
      "cwe": 79,
      "cwes": [
        79,
        89
      ],
      "vulnerability_ids": [
        "CVE-2024-3094",
        "GHSA-8r3f-844x-mdgq"
      ],
      "test": {
        "id": 3,
        "name": "ZAP Scan"
      },
      "engagement": {
        "id": 1,
        "name": "1st Quarter Engagement"
      },
      "asset": {
        "id": 2,
        "name": "Security How-to"
      },
      "organization": {
        "id": 2,
        "name": "ebooks"
      },
      "reporter": {
        "id": 1,
        "name": "admin"
      },
      "locations_count": 3,
      "tags": [
        "internal",
        "tls"
      ],
      "created": "2017-12-01T00:00:00Z",
      "updated": "2026-07-21T17:33:29.998Z"
    },
    {
      "id": 3,
      "title": "High Impact Test Finding",
      "severity": "High",
      "active": false,
      "verified": false,
      "false_p": false,
      "duplicate": true,
      "risk_accepted": false,
      "out_of_scope": false,
      "is_mitigated": false,
      "date": "2021-01-01",
      "cwe": null,
      "cwes": [],
      "vulnerability_ids": [],
      "test": {
        "id": 3,
        "name": "ZAP Scan"
      },
      "engagement": {
        "id": 1,
        "name": "1st Quarter Engagement"
      },
      "asset": {
        "id": 2,
        "name": "Security How-to"
      },
      "organization": {
        "id": 2,
        "name": "ebooks"
      },
      "reporter": {
        "id": 1,
        "name": "admin"
      },
      "locations_count": 0,
      "tags": [],
      "created": "2017-12-01T00:00:00Z",
      "updated": null
    }
  ],
  "meta": {
    "counts": {
      "total": 27,
      "active": 17,
      "verified": 18,
      "duplicate": 8,
      "severity": {
        "Critical": 0,
        "High": 13,
        "Medium": 1,
        "Low": 7,
        "Info": 6
      }
    }
  }
}
```


---

### Finding — GET list with `?fields=` opting into a detail field (`impact`)

A list returns the slim shape by default. `?fields=` may name any **detail** field (here `impact`, normally only on the detail endpoint) and it is returned on the list with no second request (§4.7). Fields are row-columns, so this is a wider `SELECT` on the same single query — never a per-row cost; the default list defers these heavy columns entirely and requesting one un-defers exactly it.

**Request**

```http
GET /api/v3-alpha/findings?id__in=2&fields=id,title,severity,impact
Authorization: Token <your-api-token>
```

**Response** — `200`

```json
{
  "count": 1,
  "next": null,
  "previous": null,
  "results": [
    {
      "id": 2,
      "title": "High Impact Test Finding",
      "severity": "High",
      "impact": "Unauthorized disclosure of customer data if exploited."
    }
  ]
}
```


---

### Finding — GET export.csv (CSV export, the second projection of the filter contract)

`GET /<resource>/export.csv` (§4.15) streams the **whole** filtered, authorized set as CSV using the identical filter/`o=`/`q=`/`fields=` contract as the list — there is no pagination (`expand`/`include`/`limit`/`offset`/`pagination`/`cursor` → 400). A `{id, name}` ref flattens to `<key>_id`/`<key>_name` columns (a location ref adds `<key>_type`); list fields (`tags`, `cwes`, `vulnerability_ids`) join with `;`. Cells starting with `= + - @` or TAB are quote-prefixed (spreadsheet formula-injection defense). A zero-row export still emits the header row.

**Request**

```http
GET /api/v3-alpha/findings/export.csv?severity=High&o=id&fields=id,title,severity,asset,cwe,cwes,vulnerability_ids,tags
Authorization: Token <your-api-token>
```

**Response** — `200`

Response headers:

```http
Content-Type: text/csv; charset=utf-8
Content-Disposition: attachment; filename="findings-export.csv"
X-API-Status: alpha
```

Body (first 4 lines):

```csv
id,title,severity,cwe,cwes,vulnerability_ids,asset_id,asset_name,tags
2,High Impact Test Finding,High,79,79;89,CVE-2024-3094;GHSA-8r3f-844x-mdgq,2,Security How-to,internal;tls
3,High Impact Test Finding,High,,,,2,Security How-to,
4,High Impact Test Finding,High,,,,2,Security How-to,
... 10 more row(s) truncated
```


---

### Finding — POST a note (sub-resource)

Notes are one generic sub-resource across resources (§4.12). Authorization is inherited from the parent finding.

**Request**

```http
POST /api/v3-alpha/findings/2/notes
Authorization: Token <your-api-token>
Content-Type: application/json

{
  "entry": "Reviewed with the security team; scheduled for the next sprint.",
  "private": false
}
```

**Response** — `201`

```json
{
  "id": 2,
  "entry": "Reviewed with the security team; scheduled for the next sprint.",
  "author": {
    "id": 1,
    "name": "admin"
  },
  "private": false,
  "edited": false,
  "created": "2026-07-21T17:33:30.235Z",
  "updated": "2026-07-21T17:33:30.235Z"
}
```


---

### Finding — GET notes (sub-resource)

List a finding's notes (paginated envelope). v2 parity: all notes are returned; `private` is a label, not a per-user read filter (§12).

**Request**

```http
GET /api/v3-alpha/findings/2/notes
Authorization: Token <your-api-token>
```

**Response** — `200`

```json
{
  "count": 1,
  "next": null,
  "previous": null,
  "results": [
    {
      "id": 2,
      "entry": "Reviewed with the security team; scheduled for the next sprint.",
      "author": {
        "id": 1,
        "name": "admin"
      },
      "private": false,
      "edited": false,
      "created": "2026-07-21T17:33:30.235Z",
      "updated": "2026-07-21T17:33:30.235Z"
    }
  ]
}
```


---

### Finding — GET locations (sub-resource, edge rows)

Finding↔Location is many-to-many with status on the edge (D5). Each row is a location ref (carrying `type`) plus the edge `status`/`audit_time`/`auditor` (§4.14).

**Request**

```http
GET /api/v3-alpha/findings/2/locations
Authorization: Token <your-api-token>
```

**Response** — `200`

```json
{
  "count": 3,
  "next": null,
  "previous": null,
  "results": [
    {
      "location": {
        "id": 2,
        "name": "ftp://localhost",
        "type": "url"
      },
      "status": "Active",
      "audit_time": null,
      "auditor": null
    },
    {
      "location": {
        "id": 9,
        "name": "https://example.com/login",
        "type": "url"
      },
      "status": "Active",
      "audit_time": null,
      "auditor": null
    },
    {
      "location": {
        "id": 10,
        "name": "https://example.com/admin",
        "type": "url"
      },
      "status": "Mitigated",
      "audit_time": null,
      "auditor": null
    }
  ]
}
```


---

### Finding — PATCH (partial update)

Partial update (PATCH-only in alpha; §12). Write payloads reference relations by integer id and only send changed fields; the response is the updated detail shape.

**Request**

```http
PATCH /api/v3-alpha/findings/240
Authorization: Token <your-api-token>
Content-Type: application/json

{
  "severity": "Medium",
  "verified": true
}
```

**Response** — `200`

```json
{
  "id": 240,
  "title": "Example Finding to Patch",
  "severity": "Medium",
  "active": true,
  "verified": true,
  "false_p": false,
  "duplicate": false,
  "risk_accepted": false,
  "out_of_scope": false,
  "is_mitigated": false,
  "date": "2026-07-21",
  "cwe": 0,
  "cwes": [],
  "vulnerability_ids": [],
  "test": {
    "id": 3,
    "name": "ZAP Scan"
  },
  "engagement": {
    "id": 1,
    "name": "1st Quarter Engagement"
  },
  "asset": {
    "id": 2,
    "name": "Security How-to"
  },
  "organization": {
    "id": 2,
    "name": "ebooks"
  },
  "reporter": {
    "id": 1,
    "name": "admin"
  },
  "locations_count": 0,
  "tags": [],
  "created": "2026-07-21T17:33:30.298Z",
  "updated": "2026-07-21T17:33:30.335Z",
  "description": "before patch",
  "mitigation": null,
  "impact": null,
  "steps_to_reproduce": null,
  "severity_justification": null,
  "references": null,
  "file_path": null,
  "line": null,
  "mitigated": null,
  "mitigated_by": null
}
```


---

### Finding — PATCH `cwes` (write a CWE list; scalar `cwe` mirrors the primary)

Finding writes accept a flat `cwes: list[int]` (§12, 2026-07-21) — symmetric with the read shape and parallel to `vulnerability_ids`. The first entry is mirrored into the scalar `cwe`; the `Finding_CWE` rows persist primary-first. An omitted `cwes` leaves existing rows untouched; an explicit `[]` clears the extras.

**Request**

```http
PATCH /api/v3-alpha/findings/241
Authorization: Token <your-api-token>
Content-Type: application/json

{
  "cwes": [
    79,
    89,
    352
  ]
}
```

**Response** — `200`

```json
{
  "id": 241,
  "title": "Example Finding for Cwes Write",
  "severity": "Low",
  "active": true,
  "verified": false,
  "false_p": false,
  "duplicate": false,
  "risk_accepted": false,
  "out_of_scope": false,
  "is_mitigated": false,
  "date": "2026-07-21",
  "cwe": 79,
  "cwes": [
    79,
    89,
    352
  ],
  "vulnerability_ids": [],
  "test": {
    "id": 3,
    "name": "ZAP Scan"
  },
  "engagement": {
    "id": 1,
    "name": "1st Quarter Engagement"
  },
  "asset": {
    "id": 2,
    "name": "Security How-to"
  },
  "organization": {
    "id": 2,
    "name": "ebooks"
  },
  "reporter": {
    "id": 1,
    "name": "admin"
  },
  "locations_count": 0,
  "tags": [],
  "created": "2026-07-21T17:33:30.374Z",
  "updated": "2026-07-21T17:33:30.411Z",
  "description": "before cwes patch",
  "mitigation": null,
  "impact": null,
  "steps_to_reproduce": null,
  "severity_justification": null,
  "references": null,
  "file_path": null,
  "line": null,
  "mitigated": null,
  "mitigated_by": null
}
```


---

### Finding — GET detail after the `cwes` PATCH (read-back)

Read-back confirms persistence: `cwes` returns the list in storage order and the scalar `cwe` mirror is the primary (first) entry.

**Request**

```http
GET /api/v3-alpha/findings/241
Authorization: Token <your-api-token>
```

**Response** — `200`

```json
{
  "id": 241,
  "title": "Example Finding for Cwes Write",
  "severity": "Low",
  "active": true,
  "verified": false,
  "false_p": false,
  "duplicate": false,
  "risk_accepted": false,
  "out_of_scope": false,
  "is_mitigated": false,
  "date": "2026-07-21",
  "cwe": 79,
  "cwes": [
    79,
    89,
    352
  ],
  "vulnerability_ids": [],
  "test": {
    "id": 3,
    "name": "ZAP Scan"
  },
  "engagement": {
    "id": 1,
    "name": "1st Quarter Engagement"
  },
  "asset": {
    "id": 2,
    "name": "Security How-to"
  },
  "organization": {
    "id": 2,
    "name": "ebooks"
  },
  "reporter": {
    "id": 1,
    "name": "admin"
  },
  "locations_count": 0,
  "tags": [],
  "created": "2026-07-21T17:33:30.374Z",
  "updated": "2026-07-21T17:33:30.411Z",
  "description": "before cwes patch",
  "mitigation": null,
  "impact": null,
  "steps_to_reproduce": null,
  "severity_justification": null,
  "references": null,
  "file_path": null,
  "line": null,
  "mitigated": null,
  "mitigated_by": null
}
```


---

### Finding — PUT (full replace)

`PUT` is a **full replace** (§4.11): it validates against the create-shaped schema (required fields enforced, unknown fields → 400) and applies the body **without** `exclude_unset`, so every omitted optional resets to its default — mirroring v2's `update(partial=False)`. The finding had `mitigation`/`impact` set, but the PUT body omits them, so they reset to `null`. The immutable parent `test` is not in the replace schema and is never reassigned (like PATCH). Finding PUT still flows through the service (JIRA / risk-acceptance / vuln-id side-effects), never route logic (I6).

**Request**

```http
PUT /api/v3-alpha/findings/242
Authorization: Token <your-api-token>
Content-Type: application/json

{
  "title": "Example finding replaced via PUT",
  "severity": "Medium",
  "description": "replaced description",
  "active": true,
  "verified": false
}
```

**Response** — `200`

```json
{
  "id": 242,
  "title": "Example Finding Replaced via PUT",
  "severity": "Medium",
  "active": true,
  "verified": false,
  "false_p": false,
  "duplicate": false,
  "risk_accepted": false,
  "out_of_scope": false,
  "is_mitigated": false,
  "date": "2026-07-21",
  "cwe": null,
  "cwes": [],
  "vulnerability_ids": [],
  "test": {
    "id": 3,
    "name": "ZAP Scan"
  },
  "engagement": {
    "id": 1,
    "name": "1st Quarter Engagement"
  },
  "asset": {
    "id": 2,
    "name": "Security How-to"
  },
  "organization": {
    "id": 2,
    "name": "ebooks"
  },
  "reporter": {
    "id": 1,
    "name": "admin"
  },
  "locations_count": 0,
  "tags": [],
  "created": "2026-07-21T17:33:30.469Z",
  "updated": "2026-07-21T17:33:30.535Z",
  "description": "replaced description",
  "mitigation": null,
  "impact": null,
  "steps_to_reproduce": null,
  "severity_justification": null,
  "references": null,
  "file_path": null,
  "line": null,
  "mitigated": null,
  "mitigated_by": null
}
```


---

### Import — POST /import (consolidated import/reimport/auto)

One endpoint for import, reimport and auto-resolve (§4.13). Destructive flags (`close_old_findings`, `close_old_findings_product_scope`) are never implied by mode; the response echoes the resolved mode + effective flags. Auto-create fields use the v3 wire names `asset_name`/`organization_name` (D11); imports are synchronous (no job resource).

**Request**

```http
POST /api/v3-alpha/import
Authorization: Token <your-api-token>
Content-Type: multipart/form-data

multipart/form-data fields (v3 imports are synchronous — there is no `background`/job field):
  mode=import                          # auto | import | reimport (default auto)
  scan_type=ZAP Scan
  engagement=4                         # import target; or test= (reimport); or
                                       #   asset_name + engagement_name (+ organization_name)
                                       #   + auto_create_context=true  to auto-create the target
  file=@0_zap_sample.xml
  active=true
  verified=true
  push_to_jira=false                   # OR-ed with the JIRA project's push_all_issues
  close_old_findings=false             # destructive flags are never implied by mode
  close_old_findings_product_scope=false
```

**Response** — `200`

```json
{
  "mode_resolved": "import",
  "test": {
    "id": 92,
    "name": "ZAP Scan"
  },
  "statistics": {
    "new": 4,
    "reactivated": 0,
    "closed": 0,
    "untouched": 0
  },
  "close_old_findings": false
}
```


---

### Asset — GET detail

A simple entity for contrast with findings: identity, `organization` ref, and the documented heavier detail fields.

**Request**

```http
GET /api/v3-alpha/assets/1
Authorization: Token <your-api-token>
```

**Response** — `200`

```json
{
  "id": 1,
  "name": "Python How-to",
  "description": "test product",
  "organization": {
    "id": 1,
    "name": "books"
  },
  "lifecycle": null,
  "tags": [],
  "created": null,
  "updated": null,
  "business_criticality": null,
  "platform": null,
  "origin": null,
  "external_audience": false,
  "internet_accessible": false,
  "asset_manager": {
    "id": 1,
    "name": "admin"
  },
  "technical_contact": {
    "id": 3,
    "name": "user2"
  },
  "team_manager": {
    "id": 2,
    "name": "user1"
  }
}
```


---

### Asset — GET list

Same envelope and grammar as findings; slim rows only on list (§4.5).

**Request**

```http
GET /api/v3-alpha/assets?limit=2
Authorization: Token <your-api-token>
```

**Response** — `200`

```json
{
  "count": 3,
  "next": "http://testserver/api/v3-alpha/assets?limit=2&offset=2",
  "previous": null,
  "results": [
    {
      "id": 1,
      "name": "Python How-to",
      "description": "test product",
      "organization": {
        "id": 1,
        "name": "books"
      },
      "lifecycle": null,
      "tags": [],
      "created": null,
      "updated": null
    },
    {
      "id": 2,
      "name": "Security How-to",
      "description": "test product",
      "organization": {
        "id": 2,
        "name": "ebooks"
      },
      "lifecycle": null,
      "tags": [],
      "created": null,
      "updated": null
    }
  ]
}
```


---

### Asset — POST (create)

Create an asset. Relations are referenced by integer id (§4.11); unknown fields are rejected (400). Response is the created detail shape (`201`).

**Request**

```http
POST /api/v3-alpha/assets
Authorization: Token <your-api-token>
Content-Type: application/json

{
  "name": "Example v3 Asset",
  "description": "Created via the v3 API examples harness",
  "organization": 1,
  "lifecycle": "production",
  "tags": [
    "pci",
    "example"
  ]
}
```

**Response** — `201`

```json
{
  "id": 4,
  "name": "Example v3 Asset",
  "description": "Created via the v3 API examples harness",
  "organization": {
    "id": 1,
    "name": "books"
  },
  "lifecycle": "production",
  "tags": [
    "example",
    "pci"
  ],
  "created": "2026-07-21T17:33:30.713Z",
  "updated": "2026-07-21T17:33:30.713Z",
  "business_criticality": null,
  "platform": null,
  "origin": null,
  "external_audience": false,
  "internet_accessible": false,
  "asset_manager": null,
  "technical_contact": null,
  "team_manager": null
}
```


---

### Asset — PATCH (partial update)

Partial update; only the changed field is sent.

**Request**

```http
PATCH /api/v3-alpha/assets/4
Authorization: Token <your-api-token>
Content-Type: application/json

{
  "description": "Updated description via PATCH"
}
```

**Response** — `200`

```json
{
  "id": 4,
  "name": "Example v3 Asset",
  "description": "Updated description via PATCH",
  "organization": {
    "id": 1,
    "name": "books"
  },
  "lifecycle": "production",
  "tags": [
    "example",
    "pci"
  ],
  "created": "2026-07-21T17:33:30.713Z",
  "updated": "2026-07-21T17:33:30.743Z",
  "business_criticality": null,
  "platform": null,
  "origin": null,
  "external_audience": false,
  "internet_accessible": false,
  "asset_manager": null,
  "technical_contact": null,
  "team_manager": null
}
```
