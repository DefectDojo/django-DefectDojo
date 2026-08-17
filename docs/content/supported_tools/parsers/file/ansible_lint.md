---
title: "Ansible Lint"
toc_hide: true
---
Import ansible-lint reports in JSON format. ansible-lint checks Ansible playbooks, roles and
collections against its rule set.

Generate a report with:

```
ansible-lint -f json playbook.yml > ansible-lint.json
```

### Scope
ansible-lint is a general linter, not solely a security scanner. Its rules cover correctness
and idiom alongside security-relevant patterns such as `risky-file-permissions` (world-writable
modes), `command-instead-of-shell` (shell use where a module exists) and unvalidated
certificates. Every rule's categories are recorded on the Finding so security-relevant results
can be filtered from stylistic ones after import.

### Severity Mapping
ansible-lint emits Code Climate formatted JSON and uses that project's severity scale rather
than one of its own:

| ansible-lint severity | DefectDojo severity |
| --- | --- |
| blocker | Critical |
| critical | High |
| major | Medium |
| minor | Low |
| info | Info |

Each issue carries a `fingerprint` that is stable for a given rule violation in a given file,
which is stored as `unique_id_from_tool`.

### Sample Scan Data
Sample Ansible Lint scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/ansible_lint).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- file_path
- line
