from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, cast

from celery.canvas import Signature

if TYPE_CHECKING:
    from collections.abc import Mapping


class _SupportsSi(Protocol):
    def si(self, *args: Any, **kwargs: Any) -> Signature: ...


class _SupportsApplyAsync(Protocol):
    def apply_async(self, args: Any | None = None, kwargs: Any | None = None, **options: Any) -> Any: ...


def _inject_async_user(kwargs: Mapping[str, Any] | None) -> dict[str, Any]:
    result: dict[str, Any] = dict(kwargs or {})
    if "async_user" not in result:
        from dojo.utils import get_current_user  # noqa: PLC0415 circular import

        result["async_user"] = get_current_user()
    return result


def dojo_create_signature(task_or_sig: _SupportsSi | Signature, *args: Any, **kwargs: Any) -> Signature:
    """
    Build a Celery signature with DefectDojo user context injected.

    - If passed a task, returns `task_or_sig.si(*args, **kwargs)`.
    - If passed an existing signature, returns a cloned signature with merged kwargs.
    """
    injected = _inject_async_user(kwargs)
    injected.pop("countdown", None)

    if isinstance(task_or_sig, Signature):
        merged_kwargs = {**(task_or_sig.kwargs or {}), **injected}
        return task_or_sig.clone(kwargs=merged_kwargs)

    return task_or_sig.si(*args, **injected)


def dojo_dispatch_task(task_or_sig: _SupportsSi | _SupportsApplyAsync | Signature, *args: Any, **kwargs: Any) -> Any:
    """
    Dispatch a task/signature using DefectDojo semantics.

    - Inject `async_user` if missing.
    - Respect `sync=True` (foreground execution) and user `block_execution`.
    - Support `countdown=<seconds>` for async dispatch.

    Returns:
    - async: AsyncResult-like return from Celery
    - sync: underlying return value of the task

    """
    from dojo.decorators import dojo_async_task_counter, we_want_async  # noqa: PLC0415 circular import

    countdown = cast("int", kwargs.pop("countdown", 0))
    injected = _inject_async_user(kwargs)

    sig = dojo_create_signature(task_or_sig if isinstance(task_or_sig, Signature) else cast("_SupportsSi", task_or_sig), *args, **injected)
    sig_kwargs = dict(sig.kwargs or {})

    if we_want_async(*sig.args, func=getattr(sig, "type", None), **sig_kwargs):
        # DojoAsyncTask.apply_async tracks async dispatch. Avoid double-counting here.
        return sig.apply_async(countdown=countdown)

    # Track foreground execution as a "created task" as well (matches historical dojo_async_task behavior)
    dojo_async_task_counter.incr(str(sig.task), args=sig.args, kwargs=sig_kwargs)

    sig_kwargs.pop("sync", None)
    sig = sig.clone(kwargs=sig_kwargs)
    eager = sig.apply()
    return eager.get(propagate=True)
