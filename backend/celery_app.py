from __future__ import annotations

import os
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Callable

try:
    from celery import Celery  # type: ignore
    from celery import chain as celery_chain  # type: ignore
except Exception:  # pragma: no cover - celery optional in tests
    Celery = None
    celery_chain = None


@dataclass
class _DummySignature:
    func: Callable[..., Any]
    args: tuple[Any, ...]
    kwargs: dict[str, Any]

    def __call__(self, previous: Any | None = None) -> Any:
        if previous is None:
            return self.func(*self.args, **self.kwargs)
        return self.func(previous, *self.args, **self.kwargs)


class _DummyChain:
    def __init__(self, *sigs: _DummySignature) -> None:
        self.sigs = sigs

    def apply_async(self) -> Any:
        result = None
        for idx, sig in enumerate(self.sigs):
            result = sig(result) if idx else sig()
        return result


class _DummyCelery:
    def __init__(self) -> None:
        self.conf = SimpleNamespace(
            task_always_eager=True,
            broker_url="memory://",
            result_backend="cache+memory://",
        )

    def task(self, *args: Any, **kwargs: Any):
        def decorator(func: Callable[..., Any]):
            def signature(*s_args: Any, **s_kwargs: Any) -> _DummySignature:
                return _DummySignature(func=func, args=s_args, kwargs=s_kwargs)

            func.s = signature  # type: ignore[attr-defined]
            func.delay = func  # type: ignore[attr-defined]
            return func

        if args and callable(args[0]) and not kwargs:
            return decorator(args[0])
        return decorator


def create_celery_app():
    if Celery is None:
        return _DummyCelery()
    app = Celery("securedev_guardian")
    app.conf.update(
        broker_url=os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0"),
        result_backend=os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0"),
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        task_soft_time_limit=int(os.environ.get("CELERY_TASK_SOFT_TIME_LIMIT", "900")),
        task_time_limit=int(os.environ.get("CELERY_TASK_TIME_LIMIT", "1200")),
        worker_concurrency=int(os.environ.get("CELERY_WORKER_CONCURRENCY", "1")),
        task_always_eager=os.environ.get("CELERY_ALWAYS_EAGER") == "1",
    )
    return app


celery_app = create_celery_app()


def chain(*tasks):
    if celery_chain is not None:
        return celery_chain(*tasks)
    return _DummyChain(*tasks)
