---
title: "IntSights Report"
toc_hide: true
---
IntSights Threat Command is a commercial Threat Intelligence platform that monitors both the open and dark web to identify threats for the Assets you care about (Domain Names, IP addresses, Brand Names, etc.).

##### Manual Import
Use the Export CSV feature in the IntSights Threat Command GUI to create an *IntSights Alerts.csv* file. This CSV
file can then be imported into Defect Dojo.

##### Automated Import

The IntSights `get-complete-alert` API only returns details for a single alert. To automate the process,
individually fetch details for each alert and append to a list. The list is then saved as the value for the key
"Alerts". This JSON object can then be imported into Defect Dojo.

Example:

    {
       "Alerts":[
          {
             "_id":"5c80egf83b4a3900078b6be6",
             "Details":{
                "Source":{
                   "URL":"https://www.htbridge.com/websec/?id=ABCDEF",
                   "Date":"2018-03-08T00:01:02.622Z",
                   "Type":"Other",
                   "NetworkType":"ClearWeb"
                },
               "Images":[
                  "5c80egf833963a40007e01e8d",
                  "5c80egf833b4a3900078b6bea",
                  "5c80egf834626bd0007bd64db"
               ],
               "Title":"HTTP headers weakness in example.com web server",
               "Tags":[],
               "Type":"ExploitableData",
               "Severity":"Critical",
               "SubType":"VulnerabilityInTechnologyInUse",
               "Description":"X-XSS-PROTECTION and CONTENT-SECURITY-POLICY headers were not sent by the server, which makes it vulnerable for various attack vectors"
            },
            "Assignees":[
               "5c3c8f99903dfd0006ge5e61"
            ],
            "FoundDate":"2018-03-08T00:01:02.622Z",
            "Assets":[
               {
                  "Type":"Domains",
                  "Value":"example.com"
               }
            ],
            "TakedownStatus":"NotSent",
            "IsFlagged":false,
            "UpdateDate":"2018-03-08T00:01:02.622Z",
            "RelatedIocs":[],
            "RelatedThreatIDs":[],
            "Closed":{
               "IsClosed":false
            }
         }
      ]
    }

### Sample Scan Data
Sample IntSights Report scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/intsights).