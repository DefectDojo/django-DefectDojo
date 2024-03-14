---
title: "pip-audit Scan"
toc_hide: true
---

Import pip-audit JSON scan report.

### File Types
This parser expects a JSON file.

The parser can handle legacy and current JSON format.

The current format has added a `dependencies` element:

    {
	  "dependencies": [
	    {
	      "name": "pyopenssl",
	      "version": "23.1.0",
	      "vulns": []
	    },
	...
	  ]
	...
	}

The legacy format does not include the `dependencies` key:

    [
	    {
	        "name": "adal",
	        "version": "1.2.2",
	        "vulns": []
	    },
    ...
    ]

### Sample Scan Data
Sample pip-audit Scan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/pip_audit).

### Link To Tool
[pip-audit](https://pypi.org/project/pip-audit/)
