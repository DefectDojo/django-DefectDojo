---
title: "Deduplication Tuning"
description: "Configure how DefectDojo identifies and manages duplicate findings"
weight: 4
audience: pro
aliases:
  - /en/working_with_findings/finding_deduplication/tune_deduplication
  - /en/triage_findings/finding_deduplication/matching_configuration
---

Deduplication Tuning is a DefectDojo Pro feature that gives you fine-grained control over how findings are deduplicated, allowing you to optimize duplicate detection for your specific security testing workflow.

## Matching Configuration

In DefectDojo Pro, matching is configured at **Settings > Finding Workflow > Matching Configuration**, beside [Dedupe Pools](/triage_findings/finding_deduplication/pro__dedupe_pools/) in the same group.

This page replaced three separate pages (Same Tool Deduplication, Cross Tool Deduplication and Reimport Deduplication). Bookmarks to those pages redirect here. Instead of picking a tool from a dropdown on one of three pages, every tool is listed once with a column for each of the three matching kinds:

- **Same Tool**: how repeated scans from one tool are recognised as the same finding.
- **Cross Tool**: how findings from different tools are matched against each other.
- **Reimport**: which formula a reimport uses inside its own test.

A tool's row shows the algorithm in force for each kind, how many hash fields it uses, and whether anyone has changed it from the shipped default.

### Changing a tool's matching

In a tool's row, select the algorithm shown under the matching kind you want to change to edit that kind's algorithm, its hash fields, or both. Because a matching change decides which findings are treated as the same finding, it is not saved directly:

1. Choose the new algorithm, the new hash fields, or both. The page explains what each algorithm matches on.
2. Select **Review Impact**. DefectDojo reports how many findings of that tool are in scope, and warns you about the two things that are easy to miss (see below).
3. Confirm you understand the change, then select **Save**.

**The two axes behave very differently, and the impact review says which one you are moving.**

- **Changing the algorithm** selects which stored value candidates are looked up by. Nothing is recomputed, and the change decides what the next import compares; existing duplicate links are left exactly as they are. The review warns you when the new algorithm would leave findings with no identity to match on at all: a tool whose findings carry no unique ID matches nothing once the algorithm requires one, and nothing errors when that happens.
- **Changing the hash fields** changes the value stored on every finding of that tool, so every hash already stored for it becomes stale. Applying queues a background recompute of the tool's whole backlog. Until that finishes, the tool's findings are hashed under two different definitions and may not match each other. The review tells you how many findings will be recomputed before you commit to it.

Two rules are enforced when you save a field selection, for the reasons in [Set-based Hash Code Fields](#set-based-hash-code-fields-vulnerability-ids-and-cwes) below: a vulnerability IDs field may stand on its own, and CWE fields may not be the only criteria.

> **One configuration per tool.** Matching Configuration is instance-wide: every Asset uses the same algorithm and field list for a given tool, including Assets in a [dedupe pool](/triage_findings/finding_deduplication/pro__dedupe_pools/). Per-pool algorithm overrides are not yet available. Hash fields will stay instance-wide even when they are, because a finding stores one hash and the classic UI, the v2 API and CSV exports all read that same value, so a pool-specific field list would change what every other view of that finding shows. [Grouping](#grouping-what-counts-as-one-finding) is the one exception: it can be set for a pool.

## Grouping: what counts as one finding

By default a finding is whatever the tool's parser produces. Some parsers merge repeated report entries themselves, and most report one entry per place a problem occurs, so the same vulnerability can show up as one finding per file, URL or package. Grouping lets you decide this per tool instead. Select the tool's **Grouping** cell on Matching Configuration to change it.

| Grouping | What one finding is |
|----------|---------------------|
| **As the parser groups them** (default) | Whatever the parser produces, exactly as before. |
| **One finding per location** | Each location gets its own finding, even where the parser merged several into one. Only offered for tools whose parser keeps every location when it merges. |
| **One finding per vulnerability** | Every location of the same vulnerability is gathered into one finding. Each location keeps its own status, and the finding stays open until every location is fixed. |

Both of the location-based groupings need the [Locations](/asset_modelling/locations/pro__locations_overview/) feature. Tools using a Global algorithm keep the parser's grouping.

### How "one finding per vulnerability" decides what is the same vulnerability

It uses the tool's own matching configuration, so there is no second list of fields to maintain:

- With **Unique ID From Tool**, or **Unique ID From Tool or Hash Code** for a report entry that has an ID, entries that share the tool's ID are one vulnerability. Many tools give one result an ID and report it at several places.
- Otherwise the tool's Same Tool hash fields are used, with everything that describes a location left out (file path, line, endpoints, component version and location types). Fields listed under **Fields Left Out of the Identity** are left out too, which helps when a tool writes the location into the description.
- **When Severities Differ** decides whether one vulnerability reported at two severities becomes one finding (at the highest severity) or stays two findings.

DefectDojo refuses a setting that would change nothing, with a message saying what to set:

- **One finding per vulnerability on a tool with no Same Tool hash fields.** Without them the hash falls back to one that includes the file and line, so nothing would fold. Many tools ship without hash fields, so set them first; Title, CWE, File Path and Line is a common choice.
- **Keep Severities Apart when Severity is not part of the identity.** Severity has to be one of the hash fields and must not be listed under **Fields Left Out of the Identity**. It is also refused for tools matched on **Unique ID From Tool**, because the tool's ID ignores severity. With **Unique ID From Tool or Hash Code**, report entries without an ID fold on the hash, so the same rules apply to them as to hash code. Entries that carry an ID still fold on that ID whatever their severity, so Keep Severities Apart splits only the entries without one.

A pool's grouping is checked against the instance's hash fields, because those are the ones its hash uses, and changing the instance's hash fields or algorithm checks again every pool that relies on them. A grouping change that is still Pending is checked the same way. Settings saved before these checks existed are left as they are. An edit to them is refused until they meet the checks, and so is a change to the instance's hash fields or algorithm while a pool still holds one. Other instance edits are not blocked by an older pool setting.

The same rules apply across tests: when a new test on the same Asset reports a vulnerability that already has a finding, its locations are added to that finding, attributed to the new test, instead of creating a duplicate. A reimport of that test then only changes the locations it reported. The finding closes once no test reports any of its locations.

On the folded finding:

- the file path and line shown are those of the first location;
- the severity is the highest among its active locations, and goes down when the highest location is fixed, unless someone set the severity by hand;
- the SLA starts from the earliest date any of its locations was found;
- marking the finding False Positive or Risk Accepted applies that status to every location, and a single location can still be changed afterwards.

Grouping is one setting for Same Tool and Reimport, because an import and a later reimport have to agree on what a finding is. With one finding per vulnerability, reimport also tracks locations as they change, so the finding stays the same when a line moves: the old location is mitigated and marked with where it moved, and the new one is added.

### Changing a tool's grouping

Choose the grouping, then select **Review Impact**. DefectDojo shows the tool's most recent tests with how many active findings each has now and how many it would have after the change. Confirm, then select **Submit**.

A change into, out of or within **One finding per vulnerability** changes what identifies a finding. DefectDojo first records the new identity of every existing finding in the background, and the tool's cell shows **Pending** meanwhile. Existing findings keep matching throughout, and the new grouping takes effect once every finding has its new identity. Moving between the other two groupings takes effect on the next import.

Findings imported before the change are not merged automatically. To fold them, run the consolidation command for an Asset. It reports what it would do by default, and changes nothing until you pass `--apply`:

```bash
python manage.py consolidate_folded_findings --product <asset id>
python manage.py consolidate_folded_findings --product <asset id> --apply
```

The newest finding of each group survives, and the others' locations move onto it, keeping the test that reported each one. The others become its duplicates.

To use a grouping only for some Assets, put them in a [dedupe pool](/triage_findings/finding_deduplication/pro__dedupe_pools/) and pick that pool under **Applies To**. Assets outside the pool keep the instance default.

## Same Tool Deduplication

Same Tool Deduplication is enabled by default for all security tool parsers. This ensures findings from consecutive scans using the same tool are properly deduplicated.

To adjust Same Tool Deduplication, select the tool's **Same Tool** column on **Settings > Finding Workflow > Matching Configuration** and follow the review-and-confirm steps above.

### Available Deduplication Algorithms

DefectDojo Pro offers the following deduplication methods for same-tool deduplication:

#### Hash Code
Uses a combination of selected fields to generate a unique hash. A tool's row on **Settings > Finding Workflow > Matching Configuration** shows how many fields make up its hash, and selecting the cell lets you change them.

##### Content Fingerprint

**Content Fingerprint** is a selectable hash field (available in all three configuration areas) that provides a *location-invariant* identity for static-analysis findings. It is derived from the vulnerable code snippet a tool includes in the finding, normalized so that indentation, line-number annotations, and formatting differences do not change it. Two findings about the same vulnerable code hash identically even when the code moved to a different line or file.

Content Fingerprint is computed for tools that include a code snippet in the finding description, including **Bandit**, **Gosec**, **Brakeman**, **Checkmarx One**, and any tool whose description carries a fenced code block or SARIF snippet.

> **Before selecting Content Fingerprint as a hash field**, populate fingerprints for existing findings by running `./manage.py backfill_fingerprints`. Findings imported after the feature is present get fingerprints automatically, but pre-existing findings have none. Selecting the field without backfilling makes existing and incoming findings hash differently, splitting every match until the backfill runs.

Content Fingerprint pairs well with **CWE** for tools that embed file paths or line numbers inside their titles, where other identity fields change every time the code moves. See [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/#choosing-hash-fields-for-tracked-tools).

#### Unique ID From Tool
Leverages the security tool's own internal identifier for findings, ensuring perfect deduplication when the scanner provides reliable unique IDs.

This algorithm can be useful when working with SAST scanners, or situations where a Finding can "move around" in source code as development progresses.

#### Unique ID From Tool or Hash Code
Attempts to use the tool's unique ID first, then falls back to the hash code if no unique ID is available. This provides the most flexible deduplication option.

#### Global Component
Matches findings by component name and version across **all Assets** in the instance, rather than within a single Asset or Engagement. Intended for SCA tools where the same vulnerable dependency appears in many Assets. Gated behind a feature flag and off by default; a superuser can turn it on from **Settings > Feature Flags**. An Asset in a [dedupe pool](/triage_findings/finding_deduplication/pro__dedupe_pools/) for the matching kind is bounded to that pool instead of the whole instance. See [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/) for details.

#### Global Vulnerability ID
Matches findings by their **vulnerability IDs** (CVE, GHSA, …) across **all Assets** in the instance, rather than within a single Asset or Engagement. Intended for tools that report the same CVE across many Assets. Gated behind a feature flag and off by default; a superuser can turn it on from **Settings > Feature Flags**. Like the other instance-wide algorithms it is bounded to the Asset's dedupe pool when the Asset is in one for that matching kind.

> **Two tools on the same instance-wide algorithm become mutual deduplication candidates.** When two *different* tools are both configured with an instance-wide algorithm (Global Component, or Global Vulnerability ID), their findings share a constant grouping hash, so a finding from either tool is considered for deduplication against the other on that shared dimension (component, or vulnerability ID). This is the intended cross-tool behavior: enable it only when you want those tools to dedupe together.

### Set-based Hash Code Fields (Vulnerability IDs and CWEs)

Two finding attributes hold a *set* of values rather than a single value: vulnerability IDs (CVE, GHSA, …) and CWEs. When using the **Hash Code** algorithm (Same Tool or Cross Tool), you can add the following fields to **Hash Code Fields** to control how those sets are compared:

| Field | Findings are duplicates when… |
|-------|-------------------------------|
| `vulnerability_ids` | they have the **exact same set** of vulnerability IDs |
| `vulnerability_ids_partial` | they share **at least one** vulnerability ID |
| `vulnerability_ids_subset` | one finding's vulnerability IDs are a **subset** of the other's |
| `cwes` | they have the **exact same set** of CWEs |
| `cwes_partial` | they share **at least one** CWE |
| `cwes_subset` | one finding's CWEs are a **subset** of the other's |

The `_partial` and `_subset` fields are compared per finding pair rather than folded into the hash: the remaining Hash Code Fields group the candidate findings, and the set comparison then narrows that group. (Exact matching, `vulnerability_ids` and `cwes`, is folded into the hash directly.)

**Empty values.** If a finding has no vulnerability IDs (or no CWEs) for the configured matcher:

- If Hash Code Fields also include an ordinary field (for example `title`), that field carries the identity: the set matcher is skipped for the pair and the findings can still match on the rest of the hash.
- If a set matcher is the **only** field, a finding with no values does not match anything: with nothing else to identify it, an empty set is not treated as matching every other finding.

**Configuration rules** (enforced when you save settings):

- A vulnerability IDs field (`vulnerability_ids`, `vulnerability_ids_partial`, or `vulnerability_ids_subset`) may be used on its own: a CVE or GHSA identifies a specific vulnerability instance.
- CWE fields (`cwes`, `cwes_partial`, `cwes_subset`) may **not** be the only criteria. A CWE is a weakness *class*, not a specific instance, so matching on CWE alone would merge unrelated findings. Pair a CWE matcher with an identifying field such as `title` or `file_path`.

## Cross Tool Deduplication

Cross Tool Deduplication is disabled by default, as deduplication between different security tools requires careful configuration due to variations in how tools report the same vulnerabilities.

Every tool's **Cross Tool** cell reads **Disabled** until you enable it. To enable Cross Tool Deduplication for a tool, select that cell on **Settings > Finding Workflow > Matching Configuration**, change the algorithm to Hash Code, and select the fields the hash should be built from. The editor will not save an algorithm with no fields, because cross-tool matching builds its hash from those fields and nothing else.

Cross Tool Deduplication supports the Hash Code algorithm, which is suitable for most workflows, as different tools rarely share compatible unique identifiers. For SCA tools reporting the same dependencies, [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/) is also available as a cross-tool option (off by default).

To turn Cross Tool Deduplication off again for a tool, set its algorithm back to **Disabled**. That also clears the tool's cross-tool hash fields, and the cross-tool hashes already stored for its Findings are recomputed to empty in the background. Until that finishes, other tools' imports can still match against those Findings.

Cross Tool Deduplication is scoped to the Asset, or to the Asset's [dedupe pool](/triage_findings/finding_deduplication/pro__dedupe_pools/) when it is in one for cross-tool matching.

## Reimport Deduplication

**⚠️ Reimport processes can completely discard Findings before they are recorded.  This can lead to data loss if set incorrectly, so Reimport Deduplication settings should be adjusted with caution.**

Reimport Deduplication can be adjusted for any tool listed on Matching Configuration. Universal Parsers and the Generic Findings Import parser are where it is most often changed, because what they emit varies per installation; for a shipped parser the default reimport formula is usually right.

To configure Reimport Deduplication, select the tool's **Reimport** column on **Settings > Finding Workflow > Matching Configuration**.

The following algorithm options are available for Reimport Deduplication:
- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

Reimport can completely discard Findings before they are recorded, so Reimport Deduplication settings should be adjusted with caution.

### Track Findings as Locations Change

A tool whose Reimport algorithm is **Hash Code** can also track findings as their locations change. With that enabled, a finding whose location moved between reimports (a line shift or file rename, a URL move, or a dependency version bump) is treated as the *same* finding, even if the tool re-scored its severity. One finding is maintained in place and its location history is preserved, instead of the old finding closing and an identical new one being created.

It is off by default and applies only to the Hash Code reimport algorithm (tools with a reliable Unique ID From Tool already track movement through their stable IDs). Tick it in the tool's **Reimport** column on **Settings > Finding Workflow > Matching Configuration**. Because it changes which fields the reimport hash is built from, applying it re-hashes the tool's existing findings in the background; the impact review tells you how many before you commit.

See [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/) for how the matching works, what is preserved, and guidance for enabling it on large instances.

## Upgrading from the tuner pages

The three tuner deduplication pages were replaced by Matching Configuration, and the upgrade
moves their configuration into it. The migration copies every per-tool entry from the tuner's
three stored settings into Matching Configuration rows, marks the ones you had changed from the
shipped defaults as changed, and then removes the tuner's stored settings.

**Pods may roll in either order relative to the migration.** The migration copies the tuning into
Matching Configuration rows and retires the old tuning fields from the application, but leaves
their columns in the database for this release. A pod still running the previous release keeps
reading and writing those columns and behaves exactly as before until it is rolled. A pod on the
new release that reaches a database which has not migrated yet matches without pools, reading the
old tuning where it needs to, until the migration lands. The columns are removed by a later
release, once no pod on the previous release can exist. If you would rather no import straddle
the changeover, hold imports across the roll; nothing fails if you do not.

**The migration is reversible, and you should still take a backup.** Rolling back to the previous
migration drops the new pool tables and restores the previous release's view of the settings; the
tuning columns never left. The backup is ordinary upgrade hygiene, not the only way back.

Two things to expect from the upgrade itself. The rows the migration seeds carry no audit log
entry, because they are written before their audit triggers are installed; audit history for
Matching Configuration starts with the first change made after the upgrade. And the first nightly
identity check after the upgrade may send a system notification that the cross-tool identity
changed for some tools. Those tools had cross-tool hash fields configured but no algorithm; the
previous release treated that as Hash code and the upgrade records Hash code explicitly, so the
definition moved while the stored hashes did not. The rehash it suggests is safe, recomputes the
same values, and records the new baseline so the notice does not repeat.

Permission changes for custom roles are described under [Dedupe Pools](/triage_findings/finding_deduplication/pro__dedupe_pools/#custom-roles-on-upgrade).

## Running Deduplication Retroactively on Existing Data

A common situation when first tuning matching is having a large backlog of Findings that were imported *before* the configuration changed. What happens to them depends on which axis you changed.

**Changing the hash fields re-hashes the backlog.** DefectDojo queues a background job to recompute the stored hash for every Finding from that tool, because the fields determine that value. The impact review tells you how many Findings that is before you apply.

- The job runs asynchronously, split into batches that the worker pool processes in parallel. On large instances (millions of Findings) it takes a while, and you will not see immediate changes in the Findings table. While it runs, a **Rehash Progress** card on **Settings > Finding Workflow > Matching Configuration**, below the page header, lists each tool and matching kind being re-hashed, how many of its batches are done, and its state: Queued, Running, Completed or Failed. A completed re-hash stays on the card for an hour, and a failed one for seven days.
- Until it finishes, that tool's Findings are hashed under two different definitions and may not match each other.
- Existing duplicate links are not revisited. Re-hashing changes what future comparisons produce, not what was already decided.

If you make several changes in quick succession, each queues its own job. Allow the previous one to finish before evaluating results, especially when comparing Finding counts before and after. The card follows only the latest re-hash of each tool and matching kind, so an earlier job stops being shown once a newer one is queued.

> **Note for self-hosted Pro:** the job runs in the Celery worker pool. If workers are starved or backlogged, the re-hash takes longer than expected. Check worker health if results do not appear within the timeframe you would expect for your instance size.
>
> Each batch runs in its own short-lived process, so a worker does not keep the memory a batch used. If a worker is killed partway through (for example, by the out-of-memory killer), the batches it held go back on the queue and run again, at the latest once the broker's visibility timeout passes (one hour by default for Redis, set with `DD_CELERY_BROKER_TRANSPORT_OPTIONS`). Once all of a re-hash's batches have been queued, it is not planned again. Re-running a batch is safe, and the card counts it once. The batch size is `DD_REHASH_SHARD_SIZE` (default: a range of 50,000 IDs per batch); worker memory depends on how many batches run at once, not on this size.
>
> A batch that fails with an error is not run again. A batch whose process is killed is retried three times, a minute apart, unless the re-hash has only one batch. Once a batch gives up, the re-hash shows **Failed**; check the worker logs for `rehash window` errors to find the cause. After fixing it, re-hash the tool from the command line with `./manage.py dedupe --parser "<scan type>" --hash_code_only`, which recomputes the stored hashes of that tool's non-duplicate Findings in the foreground. The card keeps showing the background re-hash as **Failed** afterwards. A re-hash that goes a whole day without finishing a batch (for example, because the broker lost its messages in a restart) is also shown as **Failed**; if a batch does finish later, the re-hash returns to **Running** (or **Completed**, if that was its last batch) and the count carries on from there; reload the page to see it.

**Changing the algorithm re-hashes nothing**, by design: it selects which already-stored value is compared, so there is nothing to recompute. It decides what the next import compares, and existing duplicate links are left as they are.

If you need existing Findings re-evaluated against a new configuration, use a [dedupe pool's](/triage_findings/finding_deduplication/pro__dedupe_pools/) **Apply Now**, which re-runs deduplication over the Findings already in scope and reports what it would link before it does anything.

> **Feature flags do not gate an existing configuration.** A tool's saved matching configuration stays in effect for as long as it is configured; turning off a related feature flag does **not** retroactively revert that tool to default deduplication. To change a tool's behavior, change its algorithm on **Settings > Finding Workflow > Matching Configuration**.

## Deduplication Best Practices

For optimal results with Deduplication Tuning:

- **Start with defaults**: The preconfigured deduplication settings work well for most scenarios
- **Read the impact review before applying**: it tells you how many findings are in scope, whether a new algorithm leaves any of them with nothing to match on, and how many findings a field change will re-hash.
- **Plan retroactive re-hashes**: changing hash fields recomputes every existing Finding from that tool in the background. See [Running Deduplication Retroactively on Existing Data](#running-deduplication-retroactively-on-existing-data).
- **Test changes carefully**: After adjusting matching configuration, monitor a few imports to ensure proper behavior.
- **Use Hash Code for cross-tool deduplication**: When enabling cross-tool deduplication, select fields that reliably identify the same finding across different tools (such as vulnerability name, location, and severity).  **IMPORTANT** Each tool enabled for cross-tool deduplication **MUST** have the same fields selected.
- **Keep cross-tool sources in the same Asset, or in the same Dedupe Pool**: Cross Tool Deduplication is scoped to the Asset, or to the Asset's pool when it is in one for cross-tool matching. Findings split across Assets that share neither will not dedupe even with matching hash fields. See [Cross Tool Deduplication](#cross-tool-deduplication) above.
- **Avoid overly broad deduplication**: Cross-tool deduplication with too few hash fields may result in false duplicates
- **Backfill before selecting Content Fingerprint**: run `./manage.py backfill_fingerprints` first, then select the field: the triggered re-hash then has fingerprints to work with. See [Content Fingerprint](#content-fingerprint) above.
- **Enable location tracking between scan runs**: the toggle's automatic re-hash covers the tool's whole backlog; on large instances let it finish before the next scheduled reimport. See [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/#enabling-on-existing-data-upgrades).

By tuning deduplication settings to your specific tools, you can significantly reduce duplicate noise.

## Where a tool's matching came from

A tool's row on **Settings > Finding Workflow > Matching Configuration** marks configuration that has been changed from the shipped default. A test's **Matching Policy** panel shows the same thing from the other direction: the algorithm actually in force for that test, and the pool its Asset matches within.

That pairing is what answers "why did these two findings deduplicate differently" without a support ticket: the panel names the scope each test matched within, so two tests on the same tool with different results point at different pools rather than at a fault.