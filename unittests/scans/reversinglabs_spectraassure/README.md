# Test files

Files used by the `unittests/tools/test_reversinglabs_spectraassure_parser.py`

- FD13-FullUSB.zip-report.rl.json
- putty_win_x64-0.80.exe-report.rl.json
- HxDSetup_2.5.0.exe-report.rl.json
- azure-cli-2.84.0-x64-report.rl.json
- synthetic-shared-component-report.rl.json

## Peculiarities per file

- FD13-FullUSB.zip-report.rl.json	No CVE; 2 `threats` and 1 `secrets` policy violation
- putty_win_x64-0.80.exe-report.rl.json	One CVE Finding
- HxDSetup_2.5.0.exe-report.rl.json	216 CVE Findings: 6 CVE on 2 executables that each come in 18 language builds.
  The builds share a name and a path but not a sha256, so each is its own finding
- azure-cli-2.84.0-x64-report.rl.json	104 CVE Findings plus 1 `secrets` violation that carries secret detail;
  the only file whose CVE findings carry a purl, so it is the one that covers Locations
- synthetic-shared-component-report.rl.json	**Hand-built, not a scanner output.**
  One component carrying a CVE plus two `threats` and two `secrets` violations, in a report whose
  `report.info.file` has no sha256 and whose CVSS version is "3.1"; the same binary (same sha256) also
  sits at a second path, which is the one case where findings within a report are merged.
  No real sample has two violations on one component, which is the case that proves violation
  findings are kept apart rather than collapsed into one.

The four real reports are the scanner's output reduced by `bin/strip_scan_fixtures.py` in the
dev harness: subtrees and fields the parser never reads are removed; every remaining value is real.

The `secrets` violation in FD13 has no secret detail: its rule (SQ34201) is not the rule that
populates `metadata.secrets` in that report, so the violation -> component -> secret -> evidence
chain finds nothing to attach. azure-cli covers the case where it does.
