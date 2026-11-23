"""FROZEN: sandbox lifecycle transition table. Pure; no I/O."""

from collections.abc import Mapping

from sandfort.domain.sandbox import SandboxState

S = SandboxState

TRANSITIONS: Mapping[SandboxState, frozenset[SandboxState]] = {
    S.PENDING: frozenset({S.CREATING, S.DESTROYING}),
    S.CREATING: frozenset({S.STARTED, S.ERROR, S.DESTROYING}),
    S.STARTED: frozenset({S.STOPPING, S.DESTROYING}),
    S.STOPPING: frozenset({S.STOPPED, S.ERROR, S.DESTROYING}),
    S.STOPPED: frozenset({S.STARTING, S.DESTROYING}),
    S.STARTING: frozenset({S.STARTED, S.ERROR, S.DESTROYING}),
    S.ERROR: frozenset({S.DESTROYING}),
    S.DESTROYING: frozenset({S.DESTROYED}),
    S.DESTROYED: frozenset(),
}

TERMINAL_STATES = frozenset({S.DESTROYED})


class IllegalTransition(ValueError):
    """Raised for a transition not in ``TRANSITIONS``; services map it to InvalidState."""

    def __init__(self, source: SandboxState, target: SandboxState) -> None:
        super().__init__(f"illegal sandbox transition: {source.value} -> {target.value}")
        self.source = source
        self.target = target


def can_transition(source: SandboxState, target: SandboxState) -> bool:
    return target in TRANSITIONS[source]


def assert_transition(source: SandboxState, target: SandboxState) -> None:
    if not can_transition(source, target):
        raise IllegalTransition(source, target)


def is_terminal(state: SandboxState) -> bool:
    return state in TERMINAL_STATES
