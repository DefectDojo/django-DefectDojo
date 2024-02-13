---
title: "Threagile"
toc_hide: true
---

### File Types
DefectDojo parser accepts a .json file.  
JSON reports are created from the Threagile tool (default name `risks.json`) using the following command: 

```shell
docker run --rm -it -v "$(pwd)":/app/work threagile/threagile -verbose -model /app/work/threagile.yaml -output /app/work
``` 


### Acceptable JSON Format
Parser expects an array of finding.  All properties are strings. Required fields are the following
- "category" 
- "title" 
- "severity"
- "synthetic_id" 
- "exploitation_impact"

`catergory` fields is used to set both the title of the Finding as well as the cwe.
`most_relevant_technical_asset` field is used to determine the component.
~~~

[
     {
        "category": "unguarded-direct-datastore-access",
        "risk_status": "unchecked",
        "severity": "elevated",
        "exploitation_likelihood": "likely",
        "exploitation_impact": "medium",
        "title": "\u003cb\u003eUnguarded Direct Datastore Access\u003c/b\u003e of \u003cb\u003ePoliciesRegoStorage\u003c/b\u003e by \u003cb\u003eEnergon\u003c/b\u003e via \u003cb\u003eEnergonToPolicyRegoFileStorage\u003c/b\u003e",
        "synthetic_id": "unguarded-direct-datastore-access@energon-ta\u003eenergontopolicyregofilestorage@energon-ta@policies-rego-storage-ta",
        "most_relevant_data_asset": "",
        "most_relevant_technical_asset": "policies-rego-storage-ta",
        "most_relevant_trust_boundary": "",
        "most_relevant_shared_runtime": "",
        "most_relevant_communication_link": "energon-ta\u003eenergontopolicyregofilestorage",
        "data_breach_probability": "improbable",
        "data_breach_technical_assets": [
            "policies-rego-storage-ta"
        ]
    },
    {
        "category": "unguarded-direct-datastore-access",
        "risk_status": "in-discussion",
        "severity": "elevated",
        "exploitation_likelihood": "likely",
        "exploitation_impact": "medium",
        "title": "\u003cb\u003eUnguarded Direct Datastore Access\u003c/b\u003e of \u003cb\u003ePoliciesRegoStorage\u003c/b\u003e by \u003cb\u003eIAMSidecar\u003c/b\u003e via \u003cb\u003eIAMBachendAPIPoliciesRegoFileStorage\u003c/b\u003e",
        "synthetic_id": "unguarded-direct-datastore-access@iam-sidecar-ta\u003eiambachendapipoliciesregofilestorage@iam-sidecar-ta@policies-rego-storage-ta",
        "most_relevant_data_asset": "",
        "most_relevant_technical_asset": "policies-rego-storage-ta",
        "most_relevant_trust_boundary": "",
        "most_relevant_shared_runtime": "",
        "most_relevant_communication_link": "iam-sidecar-ta\u003eiambachendapipoliciesregofilestorage",
        "data_breach_probability": "improbable",
        "data_breach_technical_assets": [
            "policies-rego-storage-ta"
        ]
    },
    {
        "category": "unguarded-direct-datastore-access",
        "risk_status": "accepted",
        "severity": "elevated",
        "exploitation_likelihood": "likely",
        "exploitation_impact": "medium",
        "title": "\u003cb\u003eUnguarded Direct Datastore Access\u003c/b\u003e of \u003cb\u003ePoliciesRegoStorage\u003c/b\u003e by \u003cb\u003eIDMSidecar\u003c/b\u003e via \u003cb\u003eIAMSidecarPoliciesRegoFileStorage\u003c/b\u003e",
        "synthetic_id": "unguarded-direct-datastore-access@idm-sidecar-ta\u003eiamsidecarpoliciesregofilestorage@idm-sidecar-ta@policies-rego-storage-ta",
        "most_relevant_data_asset": "",
        "most_relevant_technical_asset": "policies-rego-storage-ta",
        "most_relevant_trust_boundary": "",
        "most_relevant_shared_runtime": "",
        "most_relevant_communication_link": "idm-sidecar-ta\u003eiamsidecarpoliciesregofilestorage",
        "data_breach_probability": "improbable",
        "data_breach_technical_assets": [
            "policies-rego-storage-ta"
        ]
    },
    ...
]

~~~

### Sample Scan Data
Sample Threagile scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/threagile).