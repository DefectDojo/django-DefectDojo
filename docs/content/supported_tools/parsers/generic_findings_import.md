---
title: "Using Generic Findings Import"
toc_hide: true
weight: 2
---

Open-source and Pro users can use Generic Findings Import as a method to ingest JSON or CSV files into DefectDojo which are not already in the supported Tools list.

Using Generic Findings Import will create a new Test Type in your DefectDojo instance called "`{The Name Of Your Test}` (Generic Findings Import)".  For example, this JSON content will result in a Test Type called "Example Report (Generic Findings Import)":

```
{
    "name": "Example Report",
    "findings": []
}
```

DefectDojo Pro users can also consider using the [Universal Parser](../universal_parser), a tool which allows for highly customizable JSON, XML and CSV imports.

For more information on supported parameters for Generic Findings Import, see the related [Parser Guide](../file/generic).