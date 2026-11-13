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
  (for example, "Weaponized or Active only"). Exploit Maturity is normally set by this
  feed, but it can also be **set by hand** in the Threat Intelligence panel of the Add and
  Edit Finding forms — useful when no feed covers a finding (for example, one with no CVE).
  On a finding that does reference an enriched CVE, the next sync overwrites the hand-set
  value; see [Editing Findings](/triage_findings/findings_workflows/editing_findings/#edit-finding-form-fields).
* an **Exploit Evidence filter** on the findings list (**Add Filter > Exploit Evidence**). Pick
  one or more sources (**Metasploit Module**, **Nuclei Template**, **Exploit-DB Entry**), and it keeps
  the findings where any of their vulnerability IDs has one of the sources you picked;
  **Exclude** keeps every other finding. The filter and the Threat Intelligence card can show
  different things in two cases:
  * The card and the Exploit Maturity badge describe one vulnerability ID per finding, the one
    with the strongest evidence, while the filter checks every ID. A finding with several IDs
    can match **Metasploit Module** through an ID the card does not show, so the card has no
    Metasploit chip.
  * The filter reads the current feed, while the badge holds a downgrade for the stability
    window described under [Trust and score stability](#trust-and-score-stability) (14 days by
    default). So for the length of that window after a source drops an exploit, the badge and
    the filter can disagree.
* an **"Urgent & Actively Exploited"** tile on the Priority Insights dashboard (**Overview > Insights > Priority**), counting
  active Urgent-risk findings with in-the-wild exploitation — clicking through opens the
  exact filtered findings list
* a **notification event** (`threat_intel_alert`) when an existing finding's CVE gains new
  exploit evidence, such as landing in CISA KEV or gaining a Metasploit module. Upgrades
  only — evidence quietly aging out never notifies.

## Findings reported by a GitHub advisory ID

Some scanners report a vulnerability only by its GitHub advisory ID (GHSA), not by the CVE it
stands for. When DefectDojo knows that the advisory and a CVE describe the same vulnerability,
either from the intelligence bundle or from a link recorded on your instance, the finding gets
that CVE's exploit maturity, evidence and threat score, the same as a finding that names the CVE.
The finding keeps its own vulnerability ID.

When an advisory is newly linked to a CVE, or a link is rejected, DefectDojo re-scores the
findings it affects. Findings that were already on your instance before this behavior was added
are re-scored once, in the background, after the first bundle load that follows the upgrade.

## Source ratings

Each piece of evidence behind a CVE is rated, so you can judge how far to trust it. The
**Source Ratings** panel on the finding page, and the **Source Ratings** section of the
vulnerability's page in the Vulnerability Explorer, list every rated source (a KEV entry, an
Exploit-DB exploit, a Metasploit module, a Nuclei template, a public proof of concept, a
vendor security advisory) with:

* its **source reliability**, from A (completely reliable) to F (reliability cannot be
  judged), and its **information credibility**, from 1 (confirmed by other sources) to 6
  (truth cannot be judged), on the Admiralty grading scale used in intelligence analysis
* the **attack surface** it targets: endpoint, identity, cloud, network, web application or
  supply chain
* where exploitation could be **detected**: EDR, SIEM or event logs, network monitoring, or
  nowhere practical
* the model version that rated it, and when

DefectDojo rates public threat intelligence centrally, when the signed intelligence bundle is
built, and the ratings ship inside that bundle. Your instance, air-gapped or not, never sends
anything to a model to get them. Every answer carries a confidence: one below the confidence
threshold is shown as **Unrated** instead of a guess, and hovering a rating shows what it means
and how confident it is.

Ratings are informational. They do not change Priority or Risk. The panel stays hidden on a
finding whose CVE has no rated sources.

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

## Intelligence Sources card

Superusers can check which intelligence the instance is using on the read-only
**Intelligence Sources** card under **Settings > System Settings**. The card shows:

* the version of the loaded bundle
* the bundle's age, with a warning when it is 14 days old or more
* when the bundle expires
* each source in the bundle, with its license and how fresh its data is
* the last failed load, if there was one, and why it failed
* the attributions for the sources in the bundle

A bundle loaded from a file on an air-gapped instance shows on the same card.

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

### KEV and EPSS from the bundle

The bundle a self-hosted instance already downloads also carries CISA KEV and EPSS data. After
each bundle load, DefectDojo uses it to fill in **Known Exploited (CISA KEV)**, **Ransomware Used
(CISA KEV)**, the KEV date, the CISA KEV due date and EPSS scores on your vulnerabilities and
findings, so you get them without turning on separate KEV and EPSS lookups. KEV and EPSS are
handled separately, and each one is filled in from the bundle only when all of these hold:

* Threat intelligence is on.
* The lookup for that source, under Finding Enrichment in the Tuner, is off. A lookup that is on
  always wins, so with one lookup on, the bundle supplies only the other source.
* The bundle carries fresh data for that source.

The **Sync KEV/EPSS Data** button in the Vulnerability Explorer, the daily enrichment job and the
enrichment of new CVEs at import time use the same bundle data under the same conditions.

Known Exploited and Ransomware Used mean that the CVE is listed in the CISA KEV catalog. When a
scanner, a connector or a person reports a vulnerability as exploited, that report is kept as a
separate value, **Vendor Reported Exploited**, so it is not lost when CISA does not list the CVE.
See [Findings](/asset_modelling/engagements_tests/pro__findings/#metadata).

#### The first load after upgrading

On a self-hosted instance with the KEV and EPSS lookups off, these values were empty until now,
or held whatever a scanner or a person had set. The upgrade itself, before any bundle load, moves
every such flag that no CISA KEV listing backs to **Vendor Reported Exploited** or **Vendor
Reported Ransomware**, so counts under CISA KEV can already drop at that point (see
[Findings](/asset_modelling/engagements_tests/pro__findings/#metadata)). The first bundle load
after upgrading then fills the CISA values in for every CVE the instance knows, so expect:

* **Known Exploited (CISA KEV)**, **Ransomware Used (CISA KEV)** and the KEV date to change on
  many findings, both set (CISA lists the CVE) and cleared (it does not), and priority to move
  with them. A finding that a scanner or a person reported as exploited keeps its priority,
  because priority also reads **Vendor Reported Exploited**.
* If an SLA configuration has **Cap SLA by CISA KEV Due Date** turned on, KEV-listed findings to
  have their SLA deadline pulled in to CISA's due date. Most CISA due dates are already in the
  past, so many of those findings will show as breaching their SLA right after the first load.

## Enabling it

From release 3.2.200, threat intelligence is on for every instance, with nothing to switch
on. A self-hosted instance still needs one of the bundle options under
[Self-hosted deployments](#self-hosted-deployments).

Earlier releases shipped the feature off. On those, administrators can enable it directly, or
first run it in **shadow mode**, which computes the would-be scores without changing anything
live and produces a drift report showing exactly which findings would move. Contact support
for the recommended rollout on large instances, or to switch the feature off.
