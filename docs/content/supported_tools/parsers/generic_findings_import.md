---
title: "Using Generic Findings Import"
toc_hide: true
weight: 2
---

Open-source and Pro users can use Generic Findings Import as a method to ingest JSON or CSV files into DefectDojo which are not already in the supported Tools list.

Using Generic Findings Import creates a Test Type in your DefectDojo instance based on the optional `type` field in the report. The naming rules are:

- If no `type` field is provided (or it equals the scan type), the Test Type is simply **"Generic Findings Import"**. For example, this JSON content results in the Test Type "Generic Findings Import":

  ```
  {
      "name": "Example Report",
      "findings": []
  }
  ```

- If a `type` field is provided and differs from the scan type, the Test Type is **"`{type}` Scan (Generic Findings Import)"**. For example, `"type": "Tool1"` results in the Test Type "Tool1 Scan (Generic Findings Import)":

  ```
  {
      "name": "Example Report",
      "type": "Tool1",
      "findings": []
  }
  ```

- If the `type` field already ends with the "(Generic Findings Import)" suffix, it is used verbatim (the suffix is never doubled). For example, `"type": "Tool1 (Generic Findings Import)"` results in the Test Type "Tool1 (Generic Findings Import)".

DefectDojo Pro users can also consider using the [Universal Parser](../universal_parser), a tool which allows for highly customizable JSON, XML and CSV imports.

For more information on supported parameters for Generic Findings Import, see the related [Parser Guide](../file/generic).