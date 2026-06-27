from contextlib import contextmanager
from threading import local


_state = local()


def get_current_actor():
    return getattr(_state, "actor", None)


@contextmanager
def audit_actor(actor):
    previous = get_current_actor()
    _state.actor = actor if getattr(actor, "is_authenticated", True) else None
    try:
        yield
    finally:
        _state.actor = previous
