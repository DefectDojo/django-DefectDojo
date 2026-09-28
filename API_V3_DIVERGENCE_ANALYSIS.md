# Finding write path — UI / v2 API / v3 API divergence analysis and fix proposal

Status: analysis for review. No code, tests, or plan are changed by this document.

Scope: the finding **write** path (create / update / delete). The v3 API's write path was extracted
into `dojo/finding/services.py` by reconciling two pre-existing implementations of the same behaviour:

- the **v2 API serializer** — `FindingSerializer` / `FindingCreateSerializer` in
  `dojo/finding/api/serializer.py` (`.create` / `.update` / `.validate`), plus the viewset overrides
  in `dojo/finding/api/views.py`; and
- the **classic UI** — `EditFinding` in `dojo/finding/ui/views.py` (the `process_*` form flow), with
  field-level validation in `FindingForm` (`dojo/finding/ui/forms.py`).

The extraction chose the serializer as the reference for v3 and deferred UI-only behaviours. That was
a reasonable way to ship an additive alpha, but it means **the same user action can behave differently
depending on whether it arrives via the UI or the API** — and, in one case, differently between the v2
and v3 APIs. Each such gap is a latent bug class. This document catalogues every divergence found in
the code (verified line-by-line, not taken on trust), proposes a canonical behaviour for each, and
sequences the fixes across the alpha PR and the post-alpha convergence track.

This document supersedes the working divergence table that seeded it. It is self-contained; nothing
below depends on any other note.

---

## 1. Summary

Business logic for editing a finding currently lives in three places (UI view, v2 serializer, and —
now — the v3 service). Because they were each patched independently over time, they have drifted. The
observable symptoms fall into three buckets:

1. **Side-effects the UI performs and the API does not** — when a finding is deactivated, closed, or
   flipped out of false-positive, the UI runs mitigation stamping, endpoint/location mitigation,
   retroactive false-positive history, and `last_reviewed` stamping. The API write path runs none of
   these. So a finding closed through the UI and the "same" finding closed through the API end up in
   materially different states (mitigation flags, endpoint statuses, review dates, and — for FP
   history — other findings entirely).
2. **A v2-vs-v3 regression** — deleting a JIRA-linked finding through v3 does not close or reassign the
   JIRA issue, whereas v2 (and the UI) do.
3. **Shape/consistency differences** — CWE relation resync on a scalar `cwe` update (v3 does it, v2
   does not), and a create-time JIRA "push all" asymmetry present in both APIs.

**Fix strategy.** One service layer (`dojo/finding/services.py`) becomes the single home for finding
write orchestration and its side-effects. The v2 serializer and the UI view then migrate to call it
(the convergence track), so there is exactly one place a workflow bug can live. This document decides,
per divergence, *which* behaviour the single service should implement — defaulting to the behaviour
that is correct for a security workflow rather than merely the one the serializer happened to have —
and flags which of those decisions change what a v2 API consumer sees.

**How to read the ratings.** Severity reflects the real-world consequence of the two channels
disagreeing, not the size of the diff. Most rows are low: the two implementations already agree, and
convergence is a pure refactor. The high/medium rows are where the API silently skips a workflow
control the UI enforces.

---

## 2. Divergence catalogue

Each entry states the behaviour today in all three implementations (with `file:line` anchors), the
concrete impact and its severity, the proposed canonical behaviour with rationale, and the fix plan
across the three consumers. "CONV1" = v2 serializer delegates to the service; "CONV2" = UI view
delegates to the service; "CONV3" = delete the now-dead duplicate bodies.

Entries D1–D17 correspond to the seventeen reconciled rows. D18 (mandatory closing notes) and D19
(note-creation side-effects) are divergences that were not in the original reconciliation table and
are surfaced here.

---

### D1 — Status invariants (active / verified / duplicate / false_p / risk_accepted)

- **v2 serializer:** enforced in `validate()` — update path `dojo/finding/api/serializer.py:538-554`
  (with PATCH defaults pulled from the instance at `:523-536`); create path `:714-736`.
- **UI:** enforced field-level in `FindingForm.clean()` `dojo/finding/ui/forms.py:632-640`. Note the
  "simple risk acceptance disabled" case is *not* raised in the UI — the form instead removes the
  `risk_accepted` field entirely when simple risk acceptance is off and the finding is not already
  accepted (`dojo/finding/ui/forms.py:590-595`), so the invalid state is unreachable rather than
  rejected.
- **v3 service:** `_validate_status_invariants()` `dojo/finding/services.py:83-97`, called from both
  `create_finding` (`:148-156`, defaults treat "absent" as falsy) and `update_finding`
  (`:215-223`, PATCH defaults from the instance).
- **Impact:** low. All three enforce the same four core invariants. The only observable difference is
  cosmetic: the API returns a 400 for a disabled-simple-risk-acceptance attempt, whereas the UI never
  offers the control. Both outcomes are correct for their medium.
- **Proposed canonical:** the service's ported invariants. Keep the API's explicit 400 rejection — an
  API must reject invalid input loudly rather than silently drop a field.
- **Fix plan:** service already correct. CONV1: serializer delegates — invisible to v2 (identical
  logic). CONV2: the UI keeps its field-removal UX for the simple-risk-acceptance case (a template
  concern) and delegates the four invariants; no UX change. No release note.

### D2 — Risk-acceptance processing

- **v2 serializer:** `process_risk_acceptance()` runs inside `validate()` (`:558`, defined at
  `:425-435`): `simple_risk_accept` / `risk_unaccept`, gated on `enable_simple_risk_acceptance`, before
  the field updates in `update()`.
- **UI:** `simple_risk_accept(..., perform_save=False)` / `risk_unaccept(..., perform_save=False)`
  followed by an explicit `finding.save()` (`dojo/finding/ui/views.py:919-923`, saved at `:1045-1047`).
- **v3 service:** `_process_risk_acceptance()` (`dojo/finding/services.py:100-116`) runs before the
  field updates (`:225`).
- **Impact:** low. Behaviours converge. The UI's `perform_save=False` variant is an ordering
  optimisation tied to the single form save; the trigger conditions differ slightly in wording but
  resolve to the same transitions.
- **Proposed canonical:** the service's port of the serializer path. It is the field-level authority
  and does not depend on a form's save lifecycle.
- **Fix plan:** service correct. CONV1 invisible. CONV2: the UI drops its `perform_save=False` dance
  and delegates; no behaviour change. No release note.

### D3 — JIRA push on update

- **v2 serializer:** `if push_to_jira or is_keep_in_sync(instance): push(force_sync=True)` and raise on
  failure (`dojo/finding/api/serializer.py:499-503`). The viewset ORs `push_to_jira` with the JIRA
  project's `push_all_issues` first (`dojo/finding/api/views.py:169-176`).
- **UI:** `push_to_jira = push_all_issues or checkbox or is_keep_in_sync` (`dojo/finding/ui/views.py:970`),
  then `finding.save(push_to_jira=...)` (`:1045-1047`); failures surface as page messages, not
  exceptions.
- **v3 service:** synchronous `push(force_sync=True)`, raising `ValidationError` on failure
  (`dojo/finding/services.py:260-263`); the route ORs `push_all_issues`
  (`dojo/finding/api_v3/routes.py:231-234`).
- **Impact:** low. v2 and v3 already behave identically; the UI's message-based error handling is
  appropriate for a browser and its exception-free save is appropriate for a template render.
- **Proposed canonical:** the service's synchronous push that raises on failure. An API caller needs a
  real error at request time, not a swallowed background failure.
- **Fix plan:** service correct. CONV1 invisible. CONV2: when the UI delegates, its wrapper must catch
  the raised error and translate it into a page message (so the template still renders) — a small
  adapter, not a behaviour change. No release note.

### D4 — JIRA push on create

- **v2 serializer:** `if push_to_jira: push(new_finding)` with **no** `force_sync`
  (`dojo/finding/api/serializer.py:678-679`). The create path does **not** OR `push_all_issues`: the
  viewset overrides `perform_update` but not `perform_create` (`dojo/finding/api/views.py:169`), so a
  product configured to "push all issues" does not push findings created via the API until they are
  next updated.
- **UI:** create is a separate view (add-finding), out of the reconciled edit flow.
- **v3 service:** mirrors the serializer — `if push_to_jira: push(new_finding)`
  (`dojo/finding/services.py:187-188`); the create route does not OR `push_all_issues`
  (`dojo/finding/api_v3/routes.py:198-217`).
- **Impact:** low-to-medium. The create-vs-update asymmetry is present identically in v2 and v3, so it
  is not a channel divergence — but it is a latent bug: "push all issues" quietly fails to cover
  API-created findings.
- **Proposed canonical:** honour `push_all_issues` on create as well as update, so "push all" means
  what it says regardless of channel. This is a behaviour change for v2, so treat it as a deliberate,
  release-noted convergence step rather than a silent fix.
- **Fix plan:** low priority. Optionally OR `push_all_issues` in `create_finding`'s callers (both the
  v3 route and, at CONV1, the v2 create path). Behavioural change for v2 — release note. Not required
  for alpha.

### D5 — JIRA link / unlink / change issue key

- **v2 serializer:** not supported.
- **UI:** `process_jira_form()` links, unlinks, or re-keys the JIRA issue
  (`dojo/finding/ui/views.py:977-995`).
- **v3 service:** not implemented (deferred).
- **Impact:** low. This is a UI-only capability the API never had; its absence is a feature gap, not a
  behavioural disagreement over a shared field.
- **Proposed canonical:** keep it out of the finding write contract. Linking/unlinking a JIRA issue is
  a distinct action and belongs on a dedicated JIRA sub-resource, not folded into a field write where
  it would be an API-only side-channel.
- **Fix plan:** none in the service now. CONV2: the UI keeps this logic (or it moves to a JIRA
  sub-resource service later); it does not block the UI from delegating the rest of the edit flow. No
  release note.

### D6 — Finding-group handling and group push

- **v2 serializer:** not supported.
- **UI:** `update_finding_group()` on save (`dojo/finding/ui/views.py:915-917`) and a post-save group
  push (`:1050-1051`).
- **v3 service:** not implemented (deferred).
- **Impact:** low. Group membership is a separate write concern; the API never modelled it here.
- **Proposed canonical:** keep deferred; finding-group writes belong to their own endpoint.
- **Fix plan:** none now. CONV2: the UI retains group handling outside the shared service, or it moves
  to a group sub-resource later. No release note.

### D7 — `last_reviewed` / `last_reviewed_by` stamping

- **v2 serializer:** does not stamp.
- **UI:** stamps `last_reviewed = now` and `last_reviewed_by = request.user` on **every** edit
  (`dojo/finding/ui/views.py:911-912`).
- **v3 service:** does not stamp.
- **Impact:** **medium.** `last_reviewed` feeds "stale finding" / review-age reporting. A finding
  edited through the UI is marked reviewed; the identical edit through the API is not. Review-age
  metrics therefore depend on which channel a team happens to use.
- **Canonical — DECIDED (architect, 2026-07-21): NO — API field-writes do NOT stamp `last_reviewed`.**
  The v3 service's current behaviour (no stamping on create/update field-writes) is canonical, not
  provisional. Rationale: automated/bulk field writes (tag syncs, integrations) are not reviews, and
  an API cannot distinguish a human edit from automation. `last_reviewed` stamping remains an
  *explicit-action* concern: note creation already stamps it (v2-parity note side-effects), and future
  workflow actions (`request_review`, `close`, verification transitions) are the natural stamping
  points.
- **Fix plan (updated):** v3 service — no change needed. CONV2: when the UI edit flow migrates onto
  the service, the UI's "every form edit stamps" behaviour must NOT be baked into the shared
  field-write path; if the team wants to preserve it for interactive edits, the UI layer stamps
  explicitly (or passes an explicit opt-in flag) — the shared service stays stamp-free on field
  writes. Dropping the UI stamping entirely would be a UI behaviour change — release note at CONV2
  time. (See also D19:
  note creation stamps `last_reviewed` from the note date, which is a separate, already-agreed rule.)

### D8 — Auto-mitigation side-effects on deactivation (`process_mitigated_data`)

- **v2 serializer:** does not run mitigation side-effects; `validate()` only gates *editing* the
  `mitigated` / `mitigated_by` fields (`dojo/finding/api/serializer.py:508-521`).
- **UI:** when `active` is unchecked (or `false_p` / `out_of_scope` set) and the finding is not a
  duplicate, and the user may edit mitigated data, sets `is_mitigated = True` and mitigates every
  endpoint/location status (`dojo/finding/ui/views.py:833-863`, invoked at `:938`).
- **v3 service:** not implemented (deferred).
- **Impact:** **high.** A finding deactivated through the UI becomes `is_mitigated=True` with its
  endpoint/location statuses mitigated; the same finding deactivated through the API (v2 or v3) is left
  `is_mitigated=False` with live endpoint statuses. The two are then inconsistent for metrics, SLA, and
  endpoint reporting, and the discrepancy is invisible to the caller. This is the clearest
  "same action, different result" gap.
- **Proposed canonical:** **the UI behaviour is correct** — deactivating a finding should mitigate it
  and its endpoints. Note that a shared `close_finding` helper already does exactly this consistently
  and is reachable via the v2 `close` action (`dojo/finding/api/views.py:255-284`). The real defect is
  that the *generic field-write path* lets a caller set `active=false` while bypassing the close
  workflow. Preferred long-term shape: route status-closing through the close service so there is one
  mitigation code path. Faithful interim: have `update_finding` apply the same mitigation side-effects
  (guarded by `can_edit_mitigated_data`, `dojo/finding/helper.py:204-205`) when `active` flips off.
- **Fix plan:** service gains the side-effect (as a step toward, or a call into, the shared close
  logic). This is a behavioural change for v2 when it delegates (CONV1) — a finding closed via the v2
  field-write would begin mitigating endpoints. Release note; strong candidate for a behaviour-pinning
  test before the change so the "before" state is documented. Not a clear v3-alpha bug (v3 matches v2
  today), so this belongs in convergence, not alpha.

### D9 — False-positive history (`process_false_positive_history`)

- **v2 serializer:** not implemented.
- **UI:** when a finding is reactivated out of false-positive and both `false_positive_history` and
  `retroactive_false_positive_history` are enabled, retroactively reactivates all matching findings
  (`dojo/finding/ui/views.py:865-885`, invoked at `:939`).
- **v3 service:** not implemented (deferred).
- **Impact:** **medium** (gated on a non-default setting, but high blast radius when on — it edits
  *other* findings). With retroactive FP history configured, clearing `false_p` through the UI
  cascades to sibling findings; through the API it does not.
- **Proposed canonical:** the UI behaviour. This is a configured, system-wide policy; it should apply
  regardless of the channel that triggers the transition.
- **Fix plan:** move the FP-history cascade into the service so both channels honour it. Behavioural
  change for v2 (CONV1), visible only when the setting is on — arguably a bug fix, but still worth a
  release note because it changes cross-finding state. Behaviour-pinning test first. Not alpha.

### D10 — Burp request/response persistence

- **v2 serializer:** exposes `request_response` as a read-only `SerializerMethodField`
  (`dojo/finding/api/serializer.py:331`); it cannot be written.
- **UI:** `process_burp_request_response()` writes it (`dojo/finding/ui/views.py:887-900`, invoked at
  `:940`).
- **v3 service:** not implemented (deferred).
- **Impact:** low. A UI-only write capability the API never had; a feature gap, not a disagreement.
- **Proposed canonical:** keep deferred; add as an explicit write field/sub-resource later if wanted.
- **Fix plan:** none now. CONV2: UI retains this outside the shared service. No release note.

### D11 — GitHub issue sync

- **v2 serializer:** not implemented.
- **UI:** `process_github_form()` (`dojo/finding/ui/views.py:1008-1021`, invoked at `:1035`).
- **v3 service:** not implemented (deferred).
- **Impact:** low. UI-only feature gap.
- **Proposed canonical:** keep deferred.
- **Fix plan:** none now. CONV2: UI retains it outside the shared service. No release note.

### D12 — `numerical_severity`

- **v2 serializer:** does not set it.
- **UI:** sets it explicitly on save (`dojo/finding/ui/views.py:910`).
- **v3 service:** does not set it.
- **Model:** `Finding.save()` always computes it (`dojo/finding/models.py:583`).
- **Impact:** none observable. The UI's explicit assignment is redundant with the model.
- **Proposed canonical:** rely on `Finding.save()`. Do not duplicate.
- **Fix plan:** service correct. CONV2: drop the redundant UI line when the view delegates. Invisible.

### D13 — `finding_added` notification on create

- **v2 serializer:** dispatches the `finding_added` notification
  (`dojo/finding/api/serializer.py:682-690`).
- **UI:** create is a separate view, out of scope for the edit reconciliation.
- **v3 service:** dispatches it identically (`dojo/finding/services.py:190-198`).
- **Impact:** low. v2 and v3 agree.
- **Proposed canonical:** the service's dispatch.
- **Fix plan:** service correct. CONV1 invisible. No release note.

### D14 — Notification on update

- **v2 serializer:** none on the update path itself.
- **UI:** the edit flow dispatches no finding notification (notes and tags notify through their own
  flows — see D19).
- **v3 service:** none (`update_finding` dispatches nothing).
- **Impact:** low. All agree.
- **Proposed canonical:** none on the field-write update path.
- **Fix plan:** service correct. Invisible.

### D15 — Vulnerability-id and CWE persistence

- **v2 serializer:** `save_vulnerability_ids` (also writing the first id into `Finding.cve`) and
  `save_cwes`, both guarded on the nested field being present — update
  (`dojo/finding/api/serializer.py:463-491`), create (`:644-676`). On the **scalar** `cwe` path, v2
  does **not** touch the `Finding_CWE` rows (only the nested `cwes` list does, `:489-491`).
- **UI:** the same helpers (`dojo/finding/ui/views.py:942-943`).
- **v3 service:** `save_vulnerability_ids` before save (create `:180`, update `:238-239`) with the
  `cve` mirror written pre-save (create `:168-169`); `save_cwes` on create always (`:182`) and on
  update whenever the scalar `cwe` is in the change set (`:253-254`).
- **Impact:** low-to-medium. v3 exposes a scalar `cwe` (not v2's nested `cwes` list) and **resyncs**
  the `Finding_CWE` rows when the scalar changes; v2's scalar path leaves `Finding.cwe` and its
  `Finding_CWE` rows able to drift apart.
- **Proposed canonical:** v3's resync — keep `Finding.cwe` and `Finding_CWE` consistent. It is the more
  correct of the two.
- **Fix plan:** service correct. CONV1: when v2 delegates, v2's scalar-cwe path gains the resync — a
  behavioural change (a consistency fix). Release note or silent-fix at the team's discretion;
  behaviour-pinning test first. The contract difference (scalar `cwe` vs nested `cwes`) is an
  intentional v3 simplification and stays.

### D16 — `found_by` handling

- **v2 serializer:** set when a non-empty list is provided; clear on an explicit empty list; leave
  untouched when absent — update (`dojo/finding/api/serializer.py:467-475`), create set-only
  (`:668-669`).
- **UI:** via the form.
- **v3 service:** the same set/clear/untouched semantics using an `_UNSET` sentinel to distinguish
  "absent" from "empty" (update `dojo/finding/services.py:241-245`; create `:177-178`).
- **Impact:** none observable. Matches the reference exactly.
- **Proposed canonical:** the service's ported semantics.
- **Fix plan:** service correct. CONV1 invisible.

### D17 — Delete-time dedup / grading / JIRA sync  *(table corrected)*

- **v2 viewset:** `destroy()` reads an optional `push_to_jira` query param via `get_request_boolean`
  (which returns `None` when the param is absent, `dojo/api_v2/views.py:103-109`) and calls
  `instance.delete(push_to_jira=...)` (`dojo/finding/api/views.py:178-185`).
- **UI:** the delete flow calls `finding.delete(push_to_jira=...)`.
- **v3 service:** `delete_finding()` calls `finding.delete()` with **no** `push_to_jira`
  (`dojo/finding/services.py:267-275`).
- **What that actually means.** `Finding.delete()` defaults `push_to_jira` to a sentinel
  (`DELETE_JIRA_SYNC_UNSET`, `dojo/finding/models.py:716`). Inside `finding_delete`, the JIRA
  delete-sync is gated on `jira_sync_requested = push_to_jira is None or isinstance(push_to_jira, bool)`
  (`dojo/finding/helper.py:578`). v2 passes `None` (or a real bool) ⇒ `jira_sync_requested = True`; the
  sentinel from v3 is neither ⇒ `jira_sync_requested = False`. Consequently the two JIRA delete-sync
  actions — reassigning the linked issue to the surviving duplicate original
  (`dojo/finding/helper.py:585-591`) and closing the issue for the deleted finding (`:595-601`) — are
  **both skipped on v3 deletes** and **run on v2 deletes**. The dedup-cluster reconfiguration and
  product grading run in both (they are not JIRA-gated: `dojo/finding/models.py:719-733`).
- **Correction to the original table.** The seed table framed this as merely "the service omits the
  `push_to_jira` query-param; delete-time JIRA closure is additive later." That understates it: because
  of the sentinel default, v3 deletes perform **no** JIRA delete-sync at all, which is a behavioural
  **regression against v2 and the UI**, not just a missing optional parameter.
- **Impact:** **medium-to-high.** Deleting a JIRA-linked finding through v3 leaves the JIRA issue
  untouched — not closed, and (if the finding was the original of a duplicate cluster) not reassigned to
  the surviving finding. DefectDojo and JIRA drift, silently.
- **Proposed canonical:** v3 delete should engage JIRA delete-sync exactly as v2 does. The minimal,
  faithful fix is for `delete_finding` to pass `push_to_jira=None` by default (matching v2's
  no-param behaviour), with an optional explicit override added later.
- **Fix plan:** **this is the one clear bug in v3's current choice — fix it in the alpha PR.** Change
  `delete_finding` to call `finding.delete(push_to_jira=None)` (or thread an optional argument through
  the route). No change needed for v2 (it already does this) or the UI. Invisible to v2. Add a v3
  test asserting a JIRA-linked finding's issue is closed/reassigned on delete.

### D18 — Mandatory closing notes on status change  *(not in the original table)*

- **v2 serializer:** the field-write path does not enforce mandatory closing notes. (The dedicated
  `close` action, `dojo/finding/api/views.py:255-284`, accepts a note but the generic update does not
  require one.)
- **UI:** `validate_status_change()` blocks setting a finding inactive / false-positive / out-of-scope
  unless all mandatory note types are present (`dojo/finding/ui/views.py:794-831`).
- **v3 service:** not enforced.
- **Impact:** **medium.** Where an installation configures mandatory note types, the UI refuses to
  close a finding without the required justification notes; the API (v2 and v3) closes it without them.
  An integration can therefore bypass a governance control the UI enforces.
- **Proposed canonical:** the UI behaviour is the correct governance stance, but the plain field-write
  is the wrong place to demand a note (it has no note field). The right home is the close workflow
  action, which already carries a note. Recommendation: enforce mandatory-note presence in the shared
  close path, and either reject `active=false` on the generic field-write when mandatory notes are
  configured, or document that the field-write bypasses the control and steer integrations to the close
  action.
- **Fix plan:** not alpha. Decide alongside D8 (both concern closing a finding through the field-write
  vs the close action). Behavioural change for v2 if the field-write starts rejecting note-less closes
  — potentially **breaking** for an existing integration, so this one needs a deprecation window rather
  than a silent flip.

### D19 — Note-creation side-effects  *(in progress for alpha — see §5)*

Recorded here for completeness; **not proposed** in this document because it is being implemented in v3
now by a separate work stream (the notes sub-resource). Adding a note through the UI
(`dojo/finding/ui/views.py:609-641`) stamps `last_reviewed` from the note date and
`last_reviewed_by` (`:624-625`), posts a JIRA comment when the finding or its group has an issue
(`:628-631`), and fires mention/tag notifications (`process_tag_notifications`, `:637`). See §5.

---

## 3. v2 impact assessment

The v3 alpha is additive: nothing here changes v2 today. The changes below are what a v2 API consumer
would observe **after CONV1**, when the v2 serializer delegates to the shared service and the canonical
behaviours above are adopted. Categorised by consumer-visible effect:

| Divergence | v2-visible change | Category | Recommended communication |
|---|---|---|---|
| D8 auto-mitigation on deactivate | field-write closes now mitigate `is_mitigated` + endpoint/location statuses | **behavioural** | Release note. Behaviour-pinning test first. |
| D9 false-positive history | reactivating out of `false_p` cascades to matching findings (when the setting is on) | **behavioural** | Release note (cross-finding effect), even though it is a bug fix. |
| D15 CWE resync on scalar `cwe` | scalar `cwe` update now resyncs `Finding_CWE` rows | **behavioural** | Release note or silent fix (consistency correction). |
| D4 `push_all_issues` on create | findings created via API now push to JIRA under "push all issues" | **behavioural** | Release note. Optional; lowest priority. |
| D18 mandatory closing notes | field-write may begin rejecting note-less closes | **breaking** (if adopted as a rejection) | Deprecation window; do not silent-flip. |
| D7 `last_reviewed` on edit | *pending product decision* — not yet a committed change | (t.b.d.) | Decide first; whatever lands is behavioural. |
| D1 status invariants | none (service ports v2 logic verbatim) | invisible | — |
| D2 risk acceptance | none | invisible | — |
| D3 JIRA push on update | none (v2 already does this) | invisible | — |
| D12 `numerical_severity` | none (model computes it) | invisible | — |
| D13 `finding_added` notification | none | invisible | — |
| D14 update notification | none | invisible | — |
| D16 `found_by` | none | invisible | — |
| D17 delete JIRA sync | none for v2 (v2 already syncs; the fix is on v3) | invisible | — |
| D5/D6/D10/D11 UI-only features | none (v2 never had them) | invisible | — |

**Tally of v2-visible changes:** breaking **1** (D18, only if the field-write starts rejecting
note-less closes); behavioural **4** (D8, D9, D15, D4), plus D7 pending a decision; invisible **the
remaining 12** rows (D1, D2, D3, D12, D13, D14, D16, D17, and the four deferred UI-only features D5/D6/
D10/D11 which never touched v2).

Guidance: the invisible rows are pure refactors and can ship in CONV1 with the existing `test_apiv2_*`
suite as the guard. The four behavioural rows should be layered *after* the pure refactor as separate,
individually release-noted commits, so a bisect can attribute any behaviour change to a single change.
The one potentially breaking row (D18) should go through a deprecation window.

---

## 4. Sequencing proposal

Guiding rule (from the convergence track): **behaviour-pinning tests land before each refactor**, never
after. CONV1 leans on the extensive `test_apiv2_*` suite; CONV2 needs new tests because UI-flow
coverage is thinner.

**Step 0 — Alpha PR (only clear bugs in v3's *current* choice).**
- **D17** — make `delete_finding` engage JIRA delete-sync by default (pass `push_to_jira=None`), so v3
  deletes match v2/UI. Add a v3 test asserting the linked JIRA issue is closed/reassigned on delete.
- Everything else is either already-agreed (no change) or a convergence-track change to v2/UI (not a
  v3-alpha concern). D15 (CWE resync) is v3's deliberate, already-implemented choice and stays.

**Step 1 — CONV1 pure refactor (v2 serializer → service, zero contract change).**
- Pin current v2 behaviour first (extend `test_apiv2_*` to freeze exact output, *including* the
  behaviours we intend to change later: no auto-mitigation, no FP cascade, no scalar-cwe resync).
- Refactor `FindingSerializer.update` / `FindingCreateSerializer.create` to call `create_finding` /
  `update_finding`, preserving v2 semantics exactly (parameterise the service where v2 and the desired
  canonical differ, so this step changes nothing observable).

**Step 2 — CONV1 behavioural convergence (deliberate, release-noted, one change per commit).**
- D15 CWE resync → D9 FP history → D8 auto-mitigation → (optional) D4 push-all-on-create. Each with its
  own behaviour-pinning test flipped from "old" to "new" and its own release note. D8 depends on the
  shared close logic being the mitigation home, so land the close-path consolidation first.
- D18 (mandatory notes) and D7 (`last_reviewed`) are gated on decisions, not code — resolve those
  before scheduling; D18 additionally needs a deprecation window.

**Step 3 — CONV2 (UI view → service, view by view).**
- The service must first grow the UI-only side-effects it does not yet cover, as opt-in
  parameters/hooks: D5 (JIRA link/unlink), D6 (finding-group), D7 (`last_reviewed`, per the decision),
  D8 (already added in Step 2), D9 (already added), D10 (burp), D11 (github). Only then can `EditFinding`
  delegate without losing behaviour.
- Write behaviour-pinning tests for each UI flow *before* migrating it (coverage is thin today). Start
  with the flows the service already reconciled (edit / risk-acceptance). Zero template/UX change.

**Step 4 — CONV3 (delete dead duplicates).** Remove the now-unused serializer `update`/`create`
internals and the duplicated UI `process_*` bodies, only after CONV1 and CONV2 have proven the service.

**Dependency order:** Step 0 (alpha) → Step 1 (pin + delegate v2) → Step 2 (v2 behavioural, close-path
consolidation before D8) → Step 3 (service grows UI side-effects → pin UI → migrate views) → Step 4
(delete duplicates).

---

## 5. Addendum — note-creation side-effects (in progress for alpha)

One divergence adjacent to the write path is **already being implemented in v3** by a parallel work
stream (the notes sub-resource) and is therefore recorded, not proposed, here.

Adding a note to a finding through the UI (`dojo/finding/ui/views.py:609-641`) performs three
side-effects that a naive "create a note row" implementation would miss:

1. **`last_reviewed` stamping from the note** — sets `finding.last_reviewed = new_note.date` and
   `finding.last_reviewed_by` (`:624-625`). This is a distinct, already-agreed rule and should not be
   conflated with D7 (edit-time stamping, which is still open).
2. **JIRA comment** — posts the note as a comment on the finding's JIRA issue, or the finding group's
   issue (`:628-631`).
3. **Mentions / tag notifications** — `process_tag_notifications` for `@`-mentions and tag subscribers
   (`:637`).

The v3 notes work stream should reproduce all three so that a note added via the API has the same
downstream effect as one added via the UI. It is tracked there; this document makes no separate
proposal for it beyond flagging the three side-effects as the acceptance criteria.

---

## Appendix — verification record

Every row above was checked against the code rather than taken from the seed table. All 17 reconciled
rows were verified. Material corrections and additions:

- **D17 corrected** — the delete-time JIRA sync is skipped entirely on v3 (sentinel-default gate,
  `dojo/finding/helper.py:578`), a behavioural regression against v2/UI, not a merely-omitted optional
  parameter as the seed table implied. Reclassified to a v3-alpha bug.
- **D8 sharpened** — raised to high severity and tied to the existing shared close helper; the seed
  table listed it only as "deferred".
- **D1 refined** — the UI's status invariants live in `FindingForm.clean` (`dojo/finding/ui/forms.py:632-640`);
  `validate_status_change` is a *separate*, stronger check (mandatory notes, now D18); the
  simple-risk-acceptance case is handled by field removal (`:590-595`), not a raised error.
- **D4 refined** — noted the create-vs-update `push_all_issues` asymmetry, present in both v2 and v3.
- **D15 refined** — spelled out the scalar-`cwe` resync consistency difference between v2 and v3.
- **D18 added** — mandatory closing notes, a UI governance control absent from the API, not in the seed
  table.
- **D19 added** — note-creation side-effects, in progress via the notes work stream (§5).
