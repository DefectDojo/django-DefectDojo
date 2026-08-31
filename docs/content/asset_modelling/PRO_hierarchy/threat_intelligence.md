---
title: "Threat Intelligence"
description: "Exploit and threat evidence as a first-class input to Priority and Risk"
weight: 2
audience: pro
---

DefectDojo Pro enriches your findings with **dedicated threat intelligence** — exploit
availability, known exploitation, and threat-actor activity — and factors it into Priority
and Risk. This goes well beyond EPSS and the CISA KEV flag.

## What you get

Every finding with a CVE is matched, nightly, against a curated intelligence feed built
from CISA KEV, Metasploit, Exploit-DB, Nuclei templates, and public proof-of-concept
tracking. When there's exploit evidence, the finding shows a **Threat Intelligence** card:

* an **exploit-maturity** badge — *None → PoC → Weaponized → Active in the wild*
* a **threat score** (0–100)
* **evidence chips that link to the receipt** — the KEV entry (with its listing date),
  used-in-ransomware, a Metasploit module, an Exploit-DB entry, a Nuclei template, and
  public proof-of-concept repositories
* a plain-language line explaining **why** the finding's priority rose

Beyond the card, the intelligence is a working surface across the app:

* an **Exploit Maturity column** on the findings list — sortable and filterable
  (for example, "Weaponized or Active only")
* an **"Urgent & Actively Exploited"** tile on the Priority Layout dashboard, counting
  active Urgent-risk findings with in-the-wild exploitation — clicking through opens the
  exact filtered findings list
* a **notification event** (`threat_intel_alert`) when an existing finding's CVE gains new
  exploit evidence, such as landing in CISA KEV or gaining a Metasploit module. Upgrades
  only — evidence quietly aging out never notifies.

## How it changes scoring

The Priority engine already combined severity, business context, and an "external score"
built from EPSS + KEV. Threat intelligence generalizes that external score: each kind of
exploit evidence acts as a floor on the EPSS scale.

| Evidence | Priority floor (EPSS-equivalent) |
|---|---|
| Active exploitation + ransomware/named actor | 45% |
| In CISA KEV **and** used in ransomware | 30% |
| In KEV or exploited in the wild | 20% |
| Weaponized public exploit (Metasploit / Exploit-DB) | 15% |
| Nuclei detection template exists | 12% |
| Public proof-of-concept only | 8% |
| No exploit evidence | no change |

The finding's external score is the **greater** of its EPSS-derived value and the highest
evidence floor above — so intelligence only ever *raises* a score, never lowers it, and a
finding whose EPSS already exceeds the floor is unaffected. The familiar per-Organization
**external-score scalar** in your Prioritization Engine settings scales this contribution
exactly as it always scaled EPSS/KEV.

### The actively-exploited Risk floor

The table above raises **Priority**, but proportionally to a finding's base severity. That
has a consequence worth stating plainly: a Low-severity finding carrying a CVE that is being
exploited in the wild receives only a small absolute bump, and could still sit in a low
**Risk** band. Most teams consider that wrong — "actively exploited" should never be filed
under Low.

So there is a second, categorical rule. When threat intelligence reports **active
exploitation in the wild**, the finding's Priority is raised to at least the level of a
configured Risk band, regardless of what the weighted calculation alone produced. It ships
set to **Needs Action**; each Organization can raise it to Urgent, lower it, or clear it to
switch the floor off, in Prioritization Engine settings under *Actively-Exploited Risk
Floor*.

The floor only ever raises — it never moves a finding down, and a finding that already
scores higher on its own is untouched. Because it applies to Priority, the Risk band and
Risk score follow from it automatically, so every list, filter, chart and SLA calculation
sees the same consistent number.

Two boundaries worth knowing when you map an internal policy onto the floor:

* The floor is driven by the finding's **exploit-maturity badge**: it applies exactly to
  findings whose maturity shows **Active in the wild**, and to no others — lower rungs of
  the evidence ladder (weaponized exploits, PoCs, detection templates) raise the weighted
  score but never trigger the floor. The Exploit Maturity column on the findings list
  therefore shows you, at any time, precisely the set of findings the floor governs.
* The floor responds to exploitation *evidence*, not to probability scores. An EPSS score
  by itself — however high — does not trigger the floor; EPSS contributes to the weighted
  Priority calculation instead.

## Findings without a CVE

Threat intelligence is matched by CVE. Many findings — most SAST results, secrets,
misconfigurations, custom rules — have no CVE, and no vulnerability-instance threat
intelligence exists for them anywhere (this is true of every vendor, not just DefectDojo).
Those findings:

* keep their **exact** current Priority and Risk — the feature never lowers a score
* are still prioritized by all the other engine inputs (severity, business criticality,
  exposure, and so on)
* show "No threat intelligence available — this finding has no CVE to match against" on
  the card, distinct from a CVE finding that simply has no known exploit yet

One honest consequence: in a mixed queue, as CVE-bearing findings gain exploit evidence,
no-CVE findings drop in *relative* rank even though their score is unchanged.

## Trust and score stability

* **Signed intelligence.** Every nightly bundle is cryptographically signed by DefectDojo;
  your instance refuses tampered or unsigned data. Air-gapped instances import the same
  signed bundle with an offline verification step.
* **No score flapping.** Evidence upgrades apply the night they appear. If a source
  *drops* evidence, scores hold steady for a stability window (14 days by default) — a
  feed hiccup never bounces your queue, and genuine de-escalations settle in quietly after
  the window.
* **Air-gapped support.** The daily bundle (including EPSS data) can be transferred and
  imported offline, so isolated instances get the same enrichment.

## Self-hosted deployments

DefectDojo Cloud instances need no configuration. Self-hosted instances have three options:

* **Connected (default).** The instance fetches the signed bundle nightly from
  `intel.defectdojo.com` over HTTPS. This is a destination no other DefectDojo feature
  uses, so it usually has to be allowed explicitly: open outbound 443 to that host, and on
  Kubernetes add it to your egress network policy. Note the fetch runs on the **Celery
  worker**, not the web pod, so proxy settings must reach that workload too.
* **Internal mirror.** Point `DD_THREAT_INTEL_BUNDLE_URL` (and the matching digest and
  signature URLs) at a location inside your network that you sync yourself. Signature
  verification still applies, so a mirror cannot alter the data.
* **Air-gapped.** Transfer the bundle and its signature by hand and import them with
  `manage.py load_threat_intel_bundle --file <bundle>`. The signature is verified on import.

If the instance cannot reach the feed, the feature fails closed: the run is recorded as
failed and your existing scores and evidence are left exactly as they were. Nothing degrades
except intelligence freshness.

## Enabling it

The feature ships off by default. Administrators can enable it directly, or first run it
in **shadow mode** — which computes the would-be scores without changing anything live and
produces a drift report showing exactly which findings would move — before turning it on.
Contact support or see the operations runbook for the recommended rollout on large
instances.
