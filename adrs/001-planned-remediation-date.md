# 001 - Add new Planned Remediation Date field to Finding model

### Date: 
2022-05-13

## Status

[comment]: <> (Draft | Proposed | Accepted | Rejected | Superseded)

Proposed

## Context

[comment]: <> (what the decision is about, what alternatives were considered, who has contributed, and so on)

Tracking progress against open Findings can be challenging for organizations not using the Jira integration. Defect Dojo
can be used to alert owning teams of vulnerabilities, but does not have a built-in way to forecast remediation of those
Findings.

The SLA feature provides similar functionality but does not cover the same use cases. For example, a critical Finding
without a Planned Remediation Date indicates to the security team that the owning team has not planned a fix and the
issue may need to be escalated. Conversely, Findings with Planned Remediation Dates indicates to the security team that
the owning team is working on fixes and do not need to be escalated.

## Alternatives considered

[comment]: <> (Any alternatives that were considered during the decision making process)

* Custom Note Type
* Tags
* External tracking

## Decision

[comment]: <> (What the decision is)

A new DATE field in the Finding model to store a Planned Remediation Date. This field would be added/edited by owning
teams to inform the security teams when a Finding will be remediated in production (or the environment the Finding was
discovered in).


Custom Note Types are not validated for correct format so different users will enter different date formats, making
parsing difficult.

Tags are similary difficult to enforce standardization of. Especially without Key/Value pair style tags.

External tracking creates more overhead and low adoption.

## Consequences

[comment]: <> (What happens or changes as a result of this decision)

Additional (though minor) complexity added to data models and UI presentation. 