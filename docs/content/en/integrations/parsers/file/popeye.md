---
title: "Popeye"
toc_hide: true
---

# Popeye Parser documentation.

Popeye is a utility that scans live Kubernetes cluster and reports potential issues with deployed resources and configurations. For more information about the tool, please visit the public repository https://github.com/derailed/popeye.

## Popeye reports.

Popeye offer different format to export their reports, in this case for the parser we have selected to be done with JSON option for simplicity. Support for other report types planned for future.

JSON reports have the following structure:

```json
{
    "popeye": {
        "score": 100,
        "grade": "B",
        "sanitizers": [
            {
                "sanitizer": "cluster",
                "gvr": "cluster",
                "tally": {
                    "ok": 1,
                    "info": 0,
                    "warning": 0,
                    "error": 0,
                    "score": 100
                },
                "issues": {
                    "Version": [
                        {
                            "group": "__root__",
                            "gvr": "cluster",
                            "level": 0,
                            "message": "[POP-406] K8s version OK"
                        }
                    ]
                }
            }
        ]
    }
}
```

They offer a list of "sanitizers" that is the list of scanned resources in the cluster. At the same time, each sanitizer will have a list of issues, in this case the issues names will match to specific resources of the cluster (pods, roles, clusterroles, etc.) where each one will have inside a list of specific findings for that resource (issue in the report).

This parser goes through every finding inside the issues of every sanitizer looking for the ones with level 1 (Info), 2 (Warning) or 3 (Error) to be created as findings in DefectDojo.

## Findings severity matching.

Popeye scan findings don't match to public vulnerabilities, it just looks for possible informational topic, warnings or errors in kubernetes resources definition or configuraiton, so they categorize their findings the following way:

- Severity 0: Ok
- Severity 1: Info
- Severity 2: Warning
- Severity 3: Error 

To match it to DefectDojo severity formula, Secerity 0 (Ok) findings from Popeye will be ignored as those are checks that does not need an action to be resolved. For the rest:

- Severity 1 (Info) and 3 (Error) Popeye findings will be created as Severity "Info" findings in DefectDojo.
- Severity 2 (Warning) Popeye findings will be created as Severity "Low" findings in DefectDojo.

