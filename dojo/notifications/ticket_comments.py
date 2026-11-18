"""
Extension point for the comments DefectDojo posts on its own on the tickets that track findings.

Two jobs comment without anybody writing a note: the daily SLA job (pre-breach, breaching today and
breached) and the risk acceptance workflow (accepted, unaccepted, reinstated, expiration warning and
expired). The built-in Jira integration posts those comments on Jira issues, gated by its own settings.
An integration that tracks findings somewhere else registers a handler here to post the same comments
on its own tickets, gated by its own settings.

A handler is called once per batch of findings, so it can look up the batch's tickets in one query:

    handler(event, findings, text, risk_acceptance=None)

- ``event`` is one of :data:`EVENTS`.
- ``findings`` is a list of findings.
- ``text`` is the comment: a string when every finding gets the same comment (risk acceptance), or a
  mapping of finding id to that finding's own comment (SLA). :func:`comment_text` reads either form.
- ``risk_acceptance`` is the risk acceptance the event is about, or None when there is none (a
  finding risk accepted on its own, and every SLA event).

Handlers run before the built-in integration decides whether to comment, and apart from it: a handler
that raises is logged and never stops the job, the other handlers or the built-in comment. With
nothing registered, every job behaves exactly as it does without this module.

The SLA job's "Only notify for findings with a JIRA issue" setting is extended the same way:
:func:`register_ticket_link_filter` adds a ``Q`` matching findings that have a ticket elsewhere.
"""

import logging
from collections.abc import Callable, Iterable, Mapping

from django.db.models import Q

logger = logging.getLogger(__name__)

SLA_PREBREACH = "sla_prebreach"
SLA_BREACHING = "sla_breaching"
SLA_BREACHED = "sla_breached"
RISK_ACCEPTANCE_ACCEPTED = "risk_acceptance_accepted"
RISK_ACCEPTANCE_UNACCEPTED = "risk_acceptance_unaccepted"
RISK_ACCEPTANCE_REINSTATED = "risk_acceptance_reinstated"
RISK_ACCEPTANCE_EXPIRATION_WARNING = "risk_acceptance_expiration_warning"
RISK_ACCEPTANCE_EXPIRED = "risk_acceptance_expired"

SLA_EVENTS = frozenset({SLA_PREBREACH, SLA_BREACHING, SLA_BREACHED})
RISK_ACCEPTANCE_EVENTS = frozenset({
    RISK_ACCEPTANCE_ACCEPTED,
    RISK_ACCEPTANCE_UNACCEPTED,
    RISK_ACCEPTANCE_REINSTATED,
    RISK_ACCEPTANCE_EXPIRATION_WARNING,
    RISK_ACCEPTANCE_EXPIRED,
})
EVENTS = SLA_EVENTS | RISK_ACCEPTANCE_EVENTS

_handlers: list[Callable] = []
_link_filters: list[Callable[[], Q | None]] = []


def register_ticket_comment_handler(handler: Callable) -> None:
    """
    Have ``handler`` called for every automatic ticket comment. Registering the same handler twice is a no-op.

    :param handler: ``handler(event, findings, text, risk_acceptance=None)``, see the module docstring.
    """
    if handler not in _handlers:
        _handlers.append(handler)


def unregister_ticket_comment_handler(handler: Callable) -> None:
    """Stop calling ``handler``. Unregistering a handler that is not registered is a no-op."""
    if handler in _handlers:
        _handlers.remove(handler)


def has_ticket_comment_handlers() -> bool:
    """Whether any handler is registered, so a caller can skip building a comment nobody receives."""
    return bool(_handlers)


def register_ticket_link_filter(q_factory: Callable[[], Q | None]) -> None:
    """
    Widen the SLA job's "Only notify for findings with a JIRA issue" filter.

    The ``Q`` the factory returns is OR-ed with the built-in "has a Jira issue" condition, so a finding
    tracked elsewhere is still considered. The factory is called on every SLA run, so it can import
    models lazily. Registering the same factory twice is a no-op.

    :param q_factory: A callable returning a ``Q`` over ``Finding``, or None to add nothing.
    """
    if q_factory not in _link_filters:
        _link_filters.append(q_factory)


def unregister_ticket_link_filter(q_factory: Callable[[], Q | None]) -> None:
    """Remove a factory added with :func:`register_ticket_link_filter`. A no-op when it is not registered."""
    if q_factory in _link_filters:
        _link_filters.remove(q_factory)


def ticket_link_filter() -> Q | None:
    """
    The registered filters OR-ed together, or None when there are none.

    A factory that raises is logged and left out, so a broken filter cannot stop the SLA run.
    """
    combined = None
    for q_factory in _link_filters:
        try:
            q = q_factory()
        except Exception:
            logger.exception("Ticket link filter %r failed; leaving it out of the SLA run", q_factory)
            continue
        if q is None:
            continue
        combined = q if combined is None else combined | q
    return combined


def comment_text(text: str | Mapping[int, str], finding) -> str:
    """
    The comment for one finding of a batch.

    :param text: The ``text`` a handler received.
    :param finding: One of the batch's findings.
    :return: The comment, or "" when the mapping has none for this finding.
    """
    if isinstance(text, str):
        return text
    return text.get(finding.id, "")


def dispatch_ticket_comments(event: str, findings: Iterable, text: str | Mapping[int, str], risk_acceptance=None) -> None:
    """
    Hand one batch of automatic comments to every registered handler.

    Never raises: a handler that fails is logged, and the next one still runs.

    :param event: One of :data:`EVENTS`.
    :param findings: The findings the comment is about.
    :param text: One comment for every finding, or a mapping of finding id to its own comment.
    :param risk_acceptance: The risk acceptance the event is about, if any.
    """
    if not _handlers:
        return
    findings = list(findings)
    if not findings:
        return
    for handler in _handlers:
        try:
            handler(event, findings, text, risk_acceptance=risk_acceptance)
        except Exception:
            logger.exception("Ticket comment handler %r failed for %s on %d findings", handler, event, len(findings))
