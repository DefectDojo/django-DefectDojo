# DefectDojo API v3 (alpha) — worked examples

> **Auto-generated, do not hand-edit.** Every request/response below was captured by `unittests/api_v3/test_apiv3_examples.py` (`DD_API_V3_EXAMPLES=1`, CI-excluded) making **real** in-process requests against the test fixture. Tokens are redacted; long lists are truncated to ~3 rows. Regenerate with the command in that file's docstring.

Captured: 2026-07-19T13:07:38.917110+00:00

## Conventions (see `API_V3_PLAN.md` §4)

- **Mount:** alpha lives at `/api/v3-alpha/` (moves to `/api/v3/` at beta — one migration, D1). Every response carries `X-API-Status: alpha`.
- **Auth (D8):** send an existing v2 token as `Authorization: Token <key>` (works unchanged on v3), or a Django session cookie + `X-CSRFToken` on unsafe methods.
- **Envelope (§4.3):** every list is `{count, next, previous, results, meta?}` and nothing else (I1). `next`/`previous` are opaque URLs; default `limit=25`, max `250`.
- **Refs (§4.4):** relations render as `{id, name}` (locations add `type`). Write payloads reference relations by integer id — the asymmetry is intentional (§4.11).
- **`?expand=` (§4.6):** dotted paths swap refs for slim objects inline and drive the queryset (the real N+1 fix). Budget-guarded.
- **`?fields=` (§4.7):** comma-separated allowlist; `id` is always included.
- **`?include=counts` (§4.8):** adds aggregate totals to `meta` over the filtered, authorized queryset.
- **Errors (§4.10):** RFC 9457 `application/problem+json` with a `fields` extension for validation errors.

---
### Finding — GET detail (slim + detail fields)

Retrieve a single finding. Relations render as closed `{id, name}` refs (§4.4); the parent chain (`test`/`engagement`/`product`/`product_type`) is denormalized onto the finding. `locations_count` is an annotation; the full list is a sub-resource (§4.14).

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
  "cwe": null,
  "test": {
    "id": 3,
    "name": "ZAP Scan"
  },
  "engagement": {
    "id": 1,
    "name": "1st Quarter Engagement"
  },
  "product": {
    "id": 2,
    "name": "Security How-to"
  },
  "product_type": {
    "id": 2,
    "name": "ebooks"
  },
  "reporter": {
    "id": 1,
    "name": "admin"
  },
  "locations_count": 3,
  "tags": [],
  "created": "2017-12-01T00:00:00Z",
  "updated": null,
  "description": "test finding",
  "mitigation": "test mitigation",
  "impact": "High",
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
  "cwe": null,
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
      "product": {
        "id": 2,
        "name": "Security How-to"
      },
      "product_type": {
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
    "product": {
      "id": 2,
      "name": "Security How-to"
    },
    "product_type": {
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
  "product": {
    "id": 2,
    "name": "Security How-to"
  },
  "product_type": {
    "id": 2,
    "name": "ebooks"
  },
  "reporter": {
    "id": 1,
    "name": "admin"
  },
  "tags": [],
  "created": "2017-12-01T00:00:00Z",
  "updated": null,
  "description": "test finding",
  "mitigation": "test mitigation",
  "impact": "High",
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
      "date": "2026-07-19",
      "cwe": 0,
      "test": {
        "id": 3,
        "name": "ZAP Scan"
      },
      "engagement": {
        "id": 1,
        "name": "1st Quarter Engagement"
      },
      "product": {
        "id": 2,
        "name": "Security How-to"
      },
      "product_type": {
        "id": 2,
        "name": "ebooks"
      },
      "reporter": {
        "id": 1,
        "name": "admin"
      },
      "locations_count": 0,
      "tags": [],
      "created": "2026-07-19T13:07:38.625Z",
      "updated": "2026-07-19T13:07:38.625Z"
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
      "date": "2026-07-19",
      "cwe": 0,
      "test": {
        "id": 3,
        "name": "ZAP Scan"
      },
      "engagement": {
        "id": 1,
        "name": "1st Quarter Engagement"
      },
      "product": {
        "id": 2,
        "name": "Security How-to"
      },
      "product_type": {
        "id": 2,
        "name": "ebooks"
      },
      "reporter": {
        "id": 1,
        "name": "admin"
      },
      "locations_count": 0,
      "tags": [],
      "created": "2026-07-19T13:07:38.625Z",
      "updated": "2026-07-19T13:07:38.625Z"
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
      "cwe": null,
      "test": {
        "id": 3,
        "name": "ZAP Scan"
      },
      "engagement": {
        "id": 1,
        "name": "1st Quarter Engagement"
      },
      "product": {
        "id": 2,
        "name": "Security How-to"
      },
      "product_type": {
        "id": 2,
        "name": "ebooks"
      },
      "reporter": {
        "id": 1,
        "name": "admin"
      },
      "locations_count": 3,
      "tags": [],
      "created": "2017-12-01T00:00:00Z",
      "updated": null
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
      "test": {
        "id": 3,
        "name": "ZAP Scan"
      },
      "engagement": {
        "id": 1,
        "name": "1st Quarter Engagement"
      },
      "product": {
        "id": 2,
        "name": "Security How-to"
      },
      "product_type": {
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

### Finding — POST a note (sub-resource)

Notes are one generic sub-resource across resources (§4.12). Authorization is inherited from the parent finding.

**Request**

```http
POST /api/v3-alpha/findings/2/notes
Authorization: Token <your-api-token>
Content-Type: application/json

{
  "entry": "Reviewed with the product team; scheduled for the next sprint.",
  "private": false
}
```

**Response** — `201`

```json
{
  "id": 2,
  "entry": "Reviewed with the product team; scheduled for the next sprint.",
  "author": {
    "id": 1,
    "name": "admin"
  },
  "private": false,
  "edited": false,
  "created": "2026-07-19T13:07:38.688Z",
  "updated": "2026-07-19T13:07:38.688Z"
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
      "entry": "Reviewed with the product team; scheduled for the next sprint.",
      "author": {
        "id": 1,
        "name": "admin"
      },
      "private": false,
      "edited": false,
      "created": "2026-07-19T13:07:38.688Z",
      "updated": "2026-07-19T13:07:38.688Z"
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
  "date": "2026-07-19",
  "cwe": 0,
  "test": {
    "id": 3,
    "name": "ZAP Scan"
  },
  "engagement": {
    "id": 1,
    "name": "1st Quarter Engagement"
  },
  "product": {
    "id": 2,
    "name": "Security How-to"
  },
  "product_type": {
    "id": 2,
    "name": "ebooks"
  },
  "reporter": {
    "id": 1,
    "name": "admin"
  },
  "locations_count": 0,
  "tags": [],
  "created": "2026-07-19T13:07:38.711Z",
  "updated": "2026-07-19T13:07:38.759Z",
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

### Import — POST /import (consolidated import/reimport/auto)

One endpoint for import, reimport and auto-resolve (§4.13). Destructive flags are never implied by mode; the response echoes the resolved mode + effective flags.

**Request**

```http
POST /api/v3-alpha/import
Authorization: Token <your-api-token>
Content-Type: multipart/form-data

multipart/form-data fields:
  mode=import            # auto | import | reimport (default auto)
  scan_type=ZAP Scan
  engagement=4           # or test= / product_name+engagement_name+auto_create_context
  file=@0_zap_sample.xml
  active=true
  verified=true
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

### Product — GET detail

A simple entity for contrast with findings: identity, `product_type` ref, and the documented heavier detail fields.

**Request**

```http
GET /api/v3-alpha/products/1
Authorization: Token <your-api-token>
```

**Response** — `200`

```json
{
  "id": 1,
  "name": "Python How-to",
  "description": "test product",
  "product_type": {
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
  "product_manager": {
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

### Product — GET list

Same envelope and grammar as findings; slim rows only on list (§4.5).

**Request**

```http
GET /api/v3-alpha/products?limit=2
Authorization: Token <your-api-token>
```

**Response** — `200`

```json
{
  "count": 3,
  "next": "http://testserver/api/v3-alpha/products?limit=2&offset=2",
  "previous": null,
  "results": [
    {
      "id": 1,
      "name": "Python How-to",
      "description": "test product",
      "product_type": {
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
      "product_type": {
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

### Product — POST (create)

Create a product. Relations are referenced by integer id (§4.11); unknown fields are rejected (400). Response is the created detail shape (`201`).

**Request**

```http
POST /api/v3-alpha/products
Authorization: Token <your-api-token>
Content-Type: application/json

{
  "name": "Example v3 Product",
  "description": "Created via the v3 API examples harness",
  "prod_type": 1,
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
  "name": "Example v3 Product",
  "description": "Created via the v3 API examples harness",
  "product_type": {
    "id": 1,
    "name": "books"
  },
  "lifecycle": "production",
  "tags": [
    "example",
    "pci"
  ],
  "created": "2026-07-19T13:07:38.890Z",
  "updated": "2026-07-19T13:07:38.890Z",
  "business_criticality": null,
  "platform": null,
  "origin": null,
  "external_audience": false,
  "internet_accessible": false,
  "product_manager": null,
  "technical_contact": null,
  "team_manager": null
}
```


---

### Product — PATCH (partial update)

Partial update; only the changed field is sent.

**Request**

```http
PATCH /api/v3-alpha/products/4
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
  "name": "Example v3 Product",
  "description": "Updated description via PATCH",
  "product_type": {
    "id": 1,
    "name": "books"
  },
  "lifecycle": "production",
  "tags": [
    "example",
    "pci"
  ],
  "created": "2026-07-19T13:07:38.890Z",
  "updated": "2026-07-19T13:07:38.912Z",
  "business_criticality": null,
  "platform": null,
  "origin": null,
  "external_audience": false,
  "internet_accessible": false,
  "product_manager": null,
  "technical_contact": null,
  "team_manager": null
}
```

