---
title: "Darkmoon"
toc_hide: true
---
Import the JSON findings report produced by the [Darkmoon](https://github.com/ASCIT31/Dark-Moon) open source (GPL-3.0) CLI engine.

Darkmoon is an autonomous AI penetration testing platform: an LLM orchestrates specialist agents and offensive tools and attempts to prove each finding with a real exploit. The open source CLI emits a JSON findings report, which this parser maps onto DefectDojo findings.

Compared with importing Darkmoon's generic SARIF export, this parser preserves the fields SARIF cannot carry:

- the exploitation status (`exploited`, `confirmed`, `unconfirmed`) - an exploited finding is imported as active and verified; a finding Darkmoon has seen fixed (`remediated`, `resolved`, `closed`, `fixed`) is imported as inactive and mitigated
- the full CVSS vector (mapped to the CVSSv3 field)
- the specialist agent that discovered the finding
- the MITRE ATT&CK technique and ISO 27001 control
- the raw request and response, and the evidence commands/logs used to prove the finding

### Acceptable File Type(s)
JSON. As a pentest campaign runs, the Darkmoon engine writes that campaign's findings to a JSON array on disk, one file per campaign named `vulnerabilities/<campaign_id>.json`. Import that file.

- Local install: `~/.local/share/opencode/vulnerabilities/<campaign_id>.json`
- Docker Compose stack: the data directory is volume-mounted onto the host (`./darkmoon-settings/:/root/.local/share/opencode/`), so the file is at `./darkmoon-settings/vulnerabilities/<campaign_id>.json`.

The file is a bare JSON array of finding objects (no wrapper). The parser also accepts an object that wraps the array under a `findings` key.

### Sample Scan Data
Sample Darkmoon scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/darkmoon).

### Link To Tool
See [Dark-Moon on GitHub](https://github.com/ASCIT31/Dark-Moon).

### Deduplication
This parser uses the hash_code [deduplication algorithm](/triage_findings/finding_deduplication/about_deduplication/), computed from `title`, `severity` and `component_name`.
