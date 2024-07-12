---
title: "Event: scan_added and scan_added_empty"
weight: 5
chapter: true
---

Event `scan_added_empty` describes a situation when reimport did not affect the existing test (no finding has been created or closed). 

## Event HTTP header for scan_added
```yaml
X-DefectDojo-Event: scan_added
```

## Event HTTP header for scan_added_empty
```yaml
X-DefectDojo-Event: scan_added_empty
```

## Event HTTP body
```json
{
    "description": null,
    "engagement": {
        "id": 7,
        "name": "notif eng"
    },
    "finding_count": 4,
    "findings": {
        "mitigated": [
            {
                "id": 233,
                "severity": "Medium",
                "title": "Mitigated Finding",
                "url": "http://localhost:8080/finding/233"
            }
        ],
        "new": [
            {
                "id": 232,
                "severity": "Critical",
                "title": "New Finding",
                "url": "http://localhost:8080/finding/232"
            }
        ],
        "reactivated": [
            {
                "id": 234,
                "severity": "Low",
                "title": "Reactivated Finding",
                "url": "http://localhost:8080/finding/234"
            }
        ],
        "untouched": [
            {
                "id": 235,
                "severity": "Info",
                "title": "Untouched Finding",
                "url": "http://localhost:8080/finding/235"
            }
        ]
    },
    "product": {
        "id": 4,
        "name": "notif prod"
    },
    "product_type": {
        "id": 4,
        "name": "notif prod type"
    },
    "test": {
        "id": 90,
        "title": "notif test"
    },
    "url": "http://localhost:8080/test/90",
    "user": null
}
```