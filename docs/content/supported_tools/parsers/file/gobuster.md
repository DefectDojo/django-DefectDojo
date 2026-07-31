---
title: "Gobuster"
toc_hide: true
---

Import the plain-text output file written by [gobuster](https://github.com/OJ/gobuster)'s `dir` mode,
which brute-forces paths against a web server and prints one line per path that exists.

### File Types

Plain text, as written by `gobuster dir -o`. gobuster has no JSON output for `dir` mode, so the
printed line is the interface:

```
robots.txt           (Status: 200) [Size: 49]
admin                (Status: 301) [Size: 169] [--> http://target.example.com/admin/]
```

Run gobuster with `-q` so the banner and progress footer stay out of the file. If they are present
they are skipped rather than imported.

```
gobuster dir -u https://target.example.com -w wordlist.txt -q -o gobuster.txt
```

Every finding is reported at severity **Info**. gobuster reports paths that *exist*, not paths that
are wrong; whether a discovered path matters depends on which path it is, which is a judgement about
the application rather than something gobuster measures.

Two limitations are worth knowing before you import:

- **The scanned host is not in the file.** gobuster's hit lines carry the path only, so an endpoint
  is attached only when a hit redirects to an absolute URL. Each finding says so in its description
  rather than inventing a host.
- **Only `dir` mode is parsed.** gobuster's `dns` and `vhost` modes write `Found: name` — subdomain
  and virtual-host inventory rather than a weakness — and those lines are not imported.

### Sample Scan Data

Sample Gobuster scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/gobuster).

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
