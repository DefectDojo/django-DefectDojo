---
title: "Convert an unsupported tool to Generic Findings Import"
# The page that embeds this prompt with {{< prompt "generic-findings-converter" >}}.
page: "/supported_tools/parsers/file/generic"
weight: 20
---
If DefectDojo has no parser for your tool, an AI assistant (such as Claude, ChatGPT or Copilot) can write a converter to the [Generic Findings Import JSON format](/supported_tools/parsers/file/generic/#json-format). Attach a sample of your tool's output to the conversation and give it the prompt below. The prompt lists the format rules that most often make an import fail.

Note that this use case can also be handled with DefectDojo's [Universal Parser](/import_data/pro/specialized_import/universal_parser/).  Universal Parser allows you to import any XML, CSV or JSON file, and map the fields to Finding fields in

```text
Write a [Python 3] script that converts the attached [tool name] report into
DefectDojo's "Generic Findings Import" JSON format. The script reads a file path
argument and writes the converted JSON to stdout.

The output format. Follow it exactly:
- Top level: {"type": "[ToolName]", "findings": [ ... ]}.
  Always set "type". DefectDojo names the Test Type "[ToolName] Scan (Generic
  Findings Import)" from it. Without "type" the findings mix with every other
  generic import on the instance.
- Each finding MUST have "title", "severity" and "description".
  severity is one of Critical, High, Medium, Low, Info. Map the tool's own levels
  to these explicitly. Any other value fails the whole import.
- Only use these optional keys. Any key not on this list fails the import with
  "Not allowed fields are present":
    date (YYYY-MM-DD), cwe (integer), cwes (list), cve, vulnerability_ids (list),
    cvssv3 (vector with the "CVSS:3.1/" prefix), mitigation, impact, references,
    file_path, line (integer), component_name, component_version,
    fix_available (bool), fix_version, unique_id_from_tool, vuln_id_from_tool,
    endpoints (list of URL strings), tags (list), static_finding (bool),
    dynamic_finding (bool), active (bool), verified (bool)
  The false-positive flag is "false_p", not "false_positive".
- Booleans must be JSON true/false, not strings.
- If the tool gives each issue a stable ID, put it in "unique_id_from_tool".
  This is the most important field: DefectDojo uses it to recognize the same
  finding across runs, so reimport does not close and recreate it when a line
  number shifts.
- Do not invent values. Leave out a key rather than filling it with a placeholder.

After the script, list the tool fields that you could not map so I can review them.
```

The prompt lists only the keys a converter usually needs. The [Finding fields](/supported_tools/parsers/file/generic/#finding-fields) table has the full list. Import a small sample of the converted output into a test Product before you use the converter on real reports.
