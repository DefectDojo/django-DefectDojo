---
title: "Dependency Check"
toc_hide: true
---
OWASP Dependency Check output can be imported in Xml format. This parser ingests the vulnerable dependencies and inherits the suppressions.

* Suppressed vulnerabilities are tagged with the tag: `suppressed`.
* Suppressed vulnerabilities are marked as mitigated.
* If the suppression is missing any `<notes>` tag, it tags them as `no_suppression_document`.

### Related dependencies

OWASP Dependency-Check's `DependencyBundlingAnalyzer` merges co-grouped artifacts into a single main dependency and lists the others under `<relatedDependencies>` in the report. The vulnerability is attached only to the main dependency; the related entries are metadata pointing to other files in the same logical component.

The parser emits one finding per vulnerability per main dependency and surfaces the related file paths in the finding's description under a `**Related Filepaths:**` block (rather than creating a separate finding per related entry, which produced N findings sharing the same title and CVE differing only in file path).

DC bundles dependencies under five scenarios:

1. **Identical content (`hashesMatch`)** — the same jar (matching sha1) found at multiple paths (e.g. packaged into multiple ear/war archives).
2. **Shaded jar (`isShadedJar`)** — a `.jar` and a `pom.xml` extracted from inside it share the same CPE.
3. **WebJar (`isWebJar`)** — a `.js` file extracted from a WebJar maps to the jar's CPE via `pkg:maven/org.webjars/<name>@<version>`.
4. **Same CPE + base path + vulnerabilities + filename match** — sibling artifacts sharing a CPE (e.g. `spring-boot`, `spring-boot-actuator`, `spring-boot-starter-jdbc` all map to the `spring_boot` CPE).
5. **NPM same name + version** — the same npm package discovered via different resolution paths (e.g. `package-lock.json` + `node_modules`).


### Sample Scan Data
Sample Dependency Check scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/dependency_check).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- file path
