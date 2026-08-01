---
title: "APKLeaks"
toc_hide: true
---

[APKLeaks](https://github.com/dwisiswant0/apkleaks) scans an Android APK for URIs, endpoints and
secrets. It decompiles the package with jadx and then applies a set of named regular expressions —
`Google_API_Key`, `Firebase`, `IP_Address`, `LinkFinder`, and around thirty more — to everything it
recovers, including resources and the manifest as well as code.

### Field mapping

| APKLeaks | DefectDojo |
|---|---|
| `results[].name` (the pattern) | `title`, `vuln_id_from_tool` |
| `package` | `component_name`, and part of `title` |
| `results[].matches[]` | `description` (as evidence), and `nb_occurences` |
| — | `severity`, a fixed value; see below |

**One finding per pattern, not per match.** APKLeaks reports no file and no line — a match is just the
matched string — so a finding per match would differ from its siblings only by that string. That would
put secret material into finding titles and emit a separate finding for every URL the link patterns
recover. The actionable unit is "this package leaks a Google API key"; the matches are its evidence, and
their count is `nb_occurences`.

**There is no severity and no CWE.** APKLeaks reports neither, and its pattern set is user-extensible
via `-p`, so a per-pattern ranking shipped in the parser would be guesswork that goes stale as soon as
someone adds a pattern. Every finding imports at **Medium**; triage by the pattern name, which is the
title.

### Every APK produces at least one finding

`LinkFinder` always matches `http://schemas.android.com/apk/res/android`, the XML namespace that every
Android manifest declares. A clean application therefore scans as one `LinkFinder` finding rather than
zero, and the `apkleaks_one_vuln.json` fixture is exactly that floor case. Treat a lone `LinkFinder`
result as a clean scan.

Relatedly: when APKLeaks matches **nothing at all** it prints `Done with nothing` and writes **no output
file**, even with `-o` given. There is therefore no such thing as an empty APKLeaks report to import.
`apkleaks_no_vuln.json` is hand-written rather than captured, to cover the parser's handling of an empty
`results` list.

### Sample Scan Data

Sample APKLeaks files are available at
[unittests/scans/apkleaks](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/apkleaks).

### Generating an importable file

```bash
pip install apkleaks
apkleaks -f app.apk --json -o apkleaks.json
```

APKLeaks needs **jadx**. If it is not on `PATH`, APKLeaks prompts interactively to download it, which
means an unattended run in CI will fail on `EOFError` rather than scanning. Install jadx and put it on
`PATH` first.

The fixtures committed with this parser were produced with **APKLeaks 2.6.3 and jadx** against a small
Android application built for the purpose; its sources are committed alongside them
(`AndroidManifest.xml`, `strings.xml`, `MainActivity.java`). Every credential-shaped value in them is an
obviously-fake placeholder, chosen so that no fixture carries a string shaped like a credential that
GitHub's secret scanning treats as live. The `many_vuln` fixture holds 10 matches across 6 patterns.
Build the application with the Android SDK build-tools:

```bash
aapt2 compile --dir res -o res.zip
aapt2 link -o base.apk -I "$ANDROID_HOME/platforms/android-34/android.jar" \
  --manifest AndroidManifest.xml res.zip
javac -d classes -classpath "$ANDROID_HOME/platforms/android-34/android.jar" MainActivity.java
d8 --output . classes/com/example/genericapp/*.class
zip -j base.apk classes.dex
zipalign -f 4 base.apk aligned.apk
apksigner sign --ks debug.jks --out generic-app.apk aligned.apk
```

The `one_vuln` fixture is the same application with the constants removed, which leaves only the
manifest namespace for `LinkFinder` to find.

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — the legacy default. With no file or line, findings
are distinguished by the pattern name in the title and the matched values in the description, so a
rotated secret is reported as a change to the existing finding rather than as a new one.
