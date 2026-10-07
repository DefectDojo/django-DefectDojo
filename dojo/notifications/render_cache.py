"""
Render a notification message once and reuse it for every recipient that reads the same.

A notification fans out to every recipient, and each channel renders its template once per
recipient. The template context is the same for all of them except ``user``, the recipient,
and most templates read only a name from it ("Hello {{ user.get_full_name }}"). Rendering a
scan_added mail with its finding links costs tens of milliseconds, so at 15,000 recipients the
render, not the delivery, is where the worker spends its time.

The cache renders once with ``user`` replaced by a recording stand-in, and keeps two things:

* every read the template made through ``user`` (the attribute chain, and the type and value
  it produced), and
* the rendered text, with each string that came from the recipient replaced by a marker.

For the next recipient it repeats those reads against the real user. When every read that
steered the render (a number, a truth test, a type, a missing attribute) comes out the same,
the template would have taken exactly the same path, so the output is the stored text with
this recipient's strings put back in, escaped exactly where the template escaped them. When
any read differs, it renders again and keeps that as another variant.

The stand-in only allows what Django's template engine itself does with a context value:
attribute lookups, no-argument calls, truth tests, and turning a string into output through
``escape`` or ``render_value_in_context``. Anything else (comparing a value, measuring it,
slicing it, handing it to a filter that rewrites it, putting it in a JSON dump) marks the
render as opaque. An opaque render is thrown away and the template is rendered again with
the real user, and from then on that template is rendered per recipient, as before. So the
cache either reproduces the direct render or steps aside; it never guesses.

One known difference: "{% now %}" is evaluated when the stored render was made, so recipients
served from it get that moment rather than the moment of their own send. No notification
template uses it.
"""

from __future__ import annotations

import datetime
import decimal
import os
import re
import secrets
import sys
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from django.template import base as template_base
from django.template import defaulttags
from django.templatetags import i18n as i18n_tags
from django.utils import html as html_utils
from django.utils import timezone, translation

if TYPE_CHECKING:
    from collections.abc import Callable

#: Values that steer a render and are compared exactly when a cached render is reused.
_SCALAR_TYPES = frozenset({
    int, float, bool, type(None), decimal.Decimal, datetime.date, datetime.datetime,
    datetime.time, datetime.timedelta, uuid.UUID,
})

#: Kinds of context value that identify the shared part of a notification by value.
_FINGERPRINT_BY_VALUE = (str, int, float, bool, type(None))

#: Distinct renders kept per template before the cache stops learning new ones.
MAX_VARIANTS = 8

#: The two places Django turns a context value into template output. A recipient string is
#: substituted back only where it reached the output through one of them.
_OUTPUT_CODE = frozenset({
    getattr(html_utils.escape, "__wrapped__", html_utils.escape).__code__,
    template_base.render_value_in_context.__code__,
})

#: Block tags that rewrite the output of what they enclose ("{% filter upper %}"), so a
#: recipient string inside one cannot be put back in afterwards.
_REWRITING_CODE = frozenset({
    defaulttags.FilterNode.render.__code__,
    defaulttags.SpacelessNode.render.__code__,
})

#: Tags that render a recipient string into a template variable when given "as <name>"
#: ("{% firstof user.first_name as n %}", "{% blocktranslate asvar v %}"). The variable then
#: holds plain text with the marker in it, which the template may measure or cut
#: ("{{ n|truncatechars:4 }}") with nothing to tell the cache, so such a render is opaque.
_ASVAR_CODE = frozenset({
    defaulttags.FirstOfNode.render.__code__,
    i18n_tags.BlockTranslateNode.render.__code__,
})

#: The template engine, Django's i18n tags, and its escaping. A recipient string has to reach
#: the output with only this code on the stack below the render call: a project template tag
#: (or the cache tag) in between could have done anything with it, so that render is opaque.
_ENGINE_FILES = (
    str(Path(template_base.__file__).parent) + os.sep,
    str(Path(html_utils.__file__).parent) + os.sep,
    i18n_tags.__file__,
    # The test runner wraps Template.render to record what was rendered; named by path so
    # production code never imports django.test.
    str(Path(template_base.__file__).parent.parent / "test" / "utils.py"),
)


class _Recorder:

    """The reads one render made through the recipient, and how its strings reached the output."""

    def __init__(self, user):
        self.user = user
        # Digits only, so a filter that changes letter case still leaves it findable.
        self.nonce = f"{secrets.randbelow(10**12):012d}"
        self.reads: list[tuple] = []
        self.output_calls: dict[int, int] = {}
        self.slots = 0
        self.opaque = False

    def marker(self, slot: int) -> str:
        # "&" is escaped by Django, so the output shows whether a slot was escaped there; the
        # mixed-case letters show whether anything changed the case of the text around it.
        return f"[{self.nonce}.{slot}&aZ]"

    def wrap(self, path: tuple, value):
        """Record what a lookup produced and return what the template should see."""
        kind = type(value)
        if kind is str:
            slot = self.slots
            self.slots += 1
            self.reads.append((path, "str", slot))
            return _Slot(self.marker(slot), self, slot, path, value)
        if kind in _SCALAR_TYPES or isinstance(value, str):
            self.reads.append((path, "value", (kind, value)))
            return value
        self.reads.append((path, "type", kind))
        proxy_class = _CallableRecipientProxy if callable(value) else _RecipientProxy
        return proxy_class(value, path, self)

    def output(self, slot: int) -> bool:
        """Count a string reaching the output; False when something else asked for it."""
        frame = sys._getframe(2)
        if frame.f_code in _OUTPUT_CODE:
            # Walking up from the escape: engine frames, then whatever called the engine (the
            # notification renderer), then NotificationRenderCache.render. Any other code
            # sitting between two engine frames is a template tag that saw the string.
            above_engine = False
            frame = frame.f_back
            while frame is not None and frame.f_code is not _RENDER_CODE:
                code = frame.f_code
                if code in _REWRITING_CODE:
                    break
                if code in _ASVAR_CODE and getattr(frame.f_locals.get("self"), "asvar", None):
                    break
                if code.co_filename.startswith(_ENGINE_FILES):
                    if above_engine:
                        break
                else:
                    above_engine = True
                frame = frame.f_back
            else:
                if frame is not None:
                    self.output_calls[slot] = self.output_calls.get(slot, 0) + 1
                    return True
        self.opaque = True
        return False


class _RecipientProxy:

    """Stands in for the recipient (or an object reached from it) while a template renders."""

    __slots__ = ("_dd_path", "_dd_recorder", "_dd_target")

    def __init__(self, target, path: tuple, recorder: _Recorder):
        self._dd_target = target
        self._dd_path = path
        self._dd_recorder = recorder

    def __getattr__(self, name: str):
        target = self._dd_target
        path = (*self._dd_path, ("attr", name))
        recorder = self._dd_recorder
        try:
            value = getattr(target, name)
        except (AttributeError, TypeError) as exc:
            recorder.reads.append((path, "raises", type(exc)))
            raise
        except Exception:
            recorder.opaque = True
            raise
        return recorder.wrap(path, value)

    @property
    def __class__(self):
        # isinstance() answers as it would for the real object, so a type check in the
        # template engine takes the same branch.
        return type(self._dd_target)

    def __dir__(self):
        return dir(self._dd_target)

    def __getitem__(self, key):
        # The template engine tries "value[bit]" before "value.bit" for every lookup. For a
        # target that cannot be indexed, fail as it would, so the engine moves on to the
        # attribute. Indexing one that can ({{ user.extra.k }}, {{ user.groups.all.0 }})
        # is not something the cache records, so that render is opaque.
        target = self._dd_target
        if not hasattr(type(target), "__getitem__"):
            msg = f"'{type(target).__name__}' object is not subscriptable"
            raise TypeError(msg)
        self._dd_recorder.opaque = True
        return target[key]

    def __bool__(self) -> bool:
        target = self._dd_target
        result = bool(target)
        recorder = self._dd_recorder
        recorder.reads.append(((*self._dd_path, ("bool",)), "value", (bool, result)))
        return result

    def __str__(self) -> str:
        target = self._dd_target
        recorder = self._dd_recorder
        text = str(target)
        if type(text) is not str:
            recorder.opaque = True
            return text
        slot = recorder.slots
        recorder.slots += 1
        recorder.reads.append(((*self._dd_path, ("str",)), "str", slot))
        if not recorder.output(slot):
            return text
        return recorder.marker(slot)

    def _dd_opaque(self):
        recorder = self._dd_recorder
        recorder.opaque = True
        return self._dd_target

    def __eq__(self, other):
        return self._dd_opaque() == other

    def __ne__(self, other):
        return self._dd_opaque() != other

    def __lt__(self, other):
        return self._dd_opaque() < other

    def __le__(self, other):
        return self._dd_opaque() <= other

    def __gt__(self, other):
        return self._dd_opaque() > other

    def __ge__(self, other):
        return self._dd_opaque() >= other

    def __hash__(self):
        return hash(self._dd_opaque())

    def __len__(self):
        return len(self._dd_opaque())

    def __iter__(self):
        return iter(self._dd_opaque())

    def __contains__(self, item):
        return item in self._dd_opaque()

    def __format__(self, spec):
        return format(self._dd_opaque(), spec)

    def __repr__(self):
        return repr(self._dd_opaque())


class _CallableRecipientProxy(_RecipientProxy):

    """A recipient method; the template engine calls it with no arguments."""

    __slots__ = ()

    def __call__(self, *args, **kwargs):
        target = self._dd_target
        recorder = self._dd_recorder
        if args or kwargs:
            recorder.opaque = True
            return target(*args, **kwargs)
        try:
            value = target()
        except Exception:
            recorder.opaque = True
            raise
        return recorder.wrap((*self._dd_path, ("call",)), value)


_SLOT_ALLOWED = frozenset({"__class__", "__dict__", "__html__", "_dd_recorder", "_dd_slot", "_dd_path", "_dd_real"})


def _slot_state(slot: _Slot) -> dict:
    # Past _Slot.__getattribute__, which would count this read as the template's.
    return object.__getattribute__(slot, "__dict__")  # noqa: PLC2801


def _slot_text(slot: _Slot) -> str:
    # The marker as a plain str, without going through _Slot.__str__.
    return str.__str__(slot)  # noqa: PLC2801


class _Slot(str):  # noqa: FURB189, SLOT000 - must be a str to every check the engine makes

    """A recipient string while a template renders: a marker that only output may consume."""

    def __new__(cls, marker: str, recorder: _Recorder, slot: int, path: tuple, real: str):
        obj = super().__new__(cls, marker)
        obj.__dict__.update(_dd_recorder=recorder, _dd_slot=slot, _dd_path=path, _dd_real=real)
        return obj

    def __getattribute__(self, name: str):
        if name not in _SLOT_ALLOWED:
            _slot_state(self)["_dd_recorder"].opaque = True
        return super().__getattribute__(name)

    def __str__(self) -> str:
        state = _slot_state(self)
        state["_dd_recorder"].output(state["_dd_slot"])
        return _slot_text(self)

    def __bool__(self) -> bool:
        state = _slot_state(self)
        result = bool(state["_dd_real"])
        state["_dd_recorder"].reads.append(((*state["_dd_path"], ("bool",)), "value", (bool, result)))
        return result

    def _dd_opaque(self) -> str:
        _slot_state(self)["_dd_recorder"].opaque = True
        return _slot_text(self)

    def __eq__(self, other):
        return self._dd_opaque() == other

    def __ne__(self, other):
        return self._dd_opaque() != other

    def __lt__(self, other):
        return self._dd_opaque() < other

    def __le__(self, other):
        return self._dd_opaque() <= other

    def __gt__(self, other):
        return self._dd_opaque() > other

    def __ge__(self, other):
        return self._dd_opaque() >= other

    def __hash__(self):
        return hash(self._dd_opaque())

    def __len__(self):
        return len(self._dd_opaque())

    def __iter__(self):
        return iter(self._dd_opaque())

    def __contains__(self, item):
        return item in self._dd_opaque()

    def __getitem__(self, key):
        return self._dd_opaque()[key]

    def __add__(self, other):
        return self._dd_opaque() + other

    def __radd__(self, other):
        return other + self._dd_opaque()

    def __mul__(self, other):
        return self._dd_opaque() * other

    __rmul__ = __mul__

    def __mod__(self, other):
        return self._dd_opaque() % other

    def __rmod__(self, other):
        return other % self._dd_opaque()

    def __format__(self, spec):
        return format(self._dd_opaque(), spec)

    def __repr__(self):
        return repr(self._dd_opaque())


class _Variant:

    """One stored render: the reads that steered it and its text with recipient strings cut out."""

    __slots__ = ("parts", "reads")

    def __init__(self, reads: list[tuple], parts: list):
        self.reads = reads
        self.parts = parts

    def strings_for(self, user) -> dict[int, str] | None:
        """This recipient's strings, or None when any read would take the render elsewhere."""
        resolved: dict[tuple, object] = {(): user}
        strings: dict[int, str] = {}
        for path, kind, expected in self.reads:
            try:
                value = _resolve(resolved, path)
            except Exception as exc:  # compared with what the recorded render saw
                if kind == "raises" and type(exc) is expected:
                    continue
                return None
            if kind == "raises":
                return None
            if kind == "str":
                if type(value) is not str:
                    return None
                strings[expected] = value
            elif kind == "value":
                expected_type, expected_value = expected
                if type(value) is not expected_type or value != expected_value:
                    return None
            elif type(value) is not expected:
                return None
        return strings

    def assemble(self, strings: dict[int, str]) -> str:
        out = []
        for part in self.parts:
            if isinstance(part, str):
                out.append(part)
            else:
                slot, escaped = part
                value = strings[slot]
                out.append(html_utils.escape(value) if escaped else value)
        return "".join(out)


def _resolve(resolved: dict, path: tuple):
    if path in resolved:
        return resolved[path]
    parent = _resolve(resolved, path[:-1])
    step = path[-1]
    if step[0] == "attr":
        value = getattr(parent, step[1])
    elif step[0] == "call":
        value = parent()
    elif step[0] == "bool":
        value = bool(parent)
    else:  # "str"
        value = str(parent)
    resolved[path] = value
    return value


def _split(recorder: _Recorder, text: str) -> list | None:
    """The render cut at each recipient string, or None when a string leaked another way."""
    pattern = re.compile(re.escape(f"[{recorder.nonce}.") + r"(\d+)(&amp;|&)aZ\]")
    parts: list = []
    seen: dict[int, int] = {}
    position = 0
    for match in pattern.finditer(text):
        parts.append(text[position:match.start()])
        slot = int(match.group(1))
        seen[slot] = seen.get(slot, 0) + 1
        parts.append((slot, match.group(2) == "&amp;"))
        position = match.end()
    parts.append(text[position:])
    if seen != recorder.output_calls:
        return None
    if any(recorder.nonce in part for part in parts if isinstance(part, str)):
        return None
    return [part for part in parts if not isinstance(part, str) or part]


class NotificationRenderCache:

    """Per-notification store of rendered messages, shared by every channel manager of one fan-out."""

    def __init__(self):
        self._entries: dict[tuple, list] = {}
        # The shared context values are fingerprinted by identity; holding them keeps an id
        # from being reused by another object while this notification is being sent.
        self._held: list = []
        self.renders = 0
        self.reuses = 0

    def _key(self, owner, event: str, notification_type: str, context: dict) -> tuple:
        # A render with no recipient (the system mail to mail_notifications_to, the system
        # Slack channel, a webhook with no owner) reads nothing through "user", so nothing
        # would tell it apart from a recipient's render: it is kept under a key of its own.
        shared = [("user", context.get("user") is None)]
        for name in sorted(context):
            if name == "user":
                continue
            value = context[name]
            if type(value) in _FINGERPRINT_BY_VALUE:
                shared.append((name, type(value), value))
            else:
                self._held.append(value)
                shared.append((name, id(value)))
        return (
            type(owner), event, notification_type, translation.get_language(),
            timezone.get_current_timezone_name(), tuple(shared),
        )

    def render(self, owner, event: str, notification_type: str, context: dict, render: Callable[[dict], str]) -> str:
        """
        The message ``render(context)`` would produce, reusing an earlier render when it can.

        :param owner: The channel manager rendering; part of the key, as subclasses may render differently.
        :param event: The notification event.
        :param notification_type: The channel ("mail", "alert", ...).
        :param context: The template context; ``context["user"]`` is the recipient.
        :param render: Renders a context into the message, exactly as without the cache.
        """
        user = context.get("user")
        key = self._key(owner, event, notification_type, context)
        entry = self._entries.get(key)
        if entry is None:
            entry = self._entries[key] = []
        elif entry is False:
            self.renders += 1
            return render(context)
        for variant in entry:
            strings = variant.strings_for(user)
            if strings is not None:
                self.reuses += 1
                return variant.assemble(strings)
        self.renders += 1
        if len(entry) >= MAX_VARIANTS:
            return render(context)
        recorder = _Recorder(user)
        recording = dict(context)
        # The first read recorded is the recipient's own type, checked like any other.
        recording["user"] = recorder.wrap((), user) if user is not None else None
        try:
            text = render(recording)
        except Exception:  # any surprise in the stand-in falls back to the plain render
            recorder.opaque = True
            text = None
        parts = None if recorder.opaque or text is None else _split(recorder, text)
        if parts is None:
            self._entries[key] = False
            return render(context)
        variant = _Variant(recorder.reads, parts)
        strings = variant.strings_for(user)
        if strings is None:
            self._entries[key] = False
            return render(context)
        entry.append(variant)
        return variant.assemble(strings)


#: Where a render starts: the stack walk in ``_Recorder.output`` stops here.
_RENDER_CODE = NotificationRenderCache.render.__code__
