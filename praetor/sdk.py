"""Agent-facing SDK.

Integration is meant to be one line at the action boundary: instead of an agent
calling a tool directly, it calls ``client.guarded(...)``. If Praetor approves,
the supplied callable runs; otherwise it is blocked. This is how Praetor stays
*non-bypassable* in practice -- the action only happens through the broker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from .orchestrator import Decision, Orchestrator


class PraetorDenied(Exception):
    """Raised when an action is blocked by Praetor."""

    def __init__(self, decision: Decision) -> None:
        super().__init__(f"Praetor denied [{decision.tier}]: {decision.reason}")
        self.decision = decision


@dataclass
class PraetorClient:
    """A thin client bound to an agent identity.

    In a deployment this would talk to the orchestrator over HTTP; here it can
    wrap an in-process :class:`Orchestrator` for tests and the local demo.
    """

    agent_id: str
    orchestrator: Orchestrator

    def request(self, action: str, resource: str = "", metadata: Optional[dict] = None) -> Decision:
        return self.orchestrator.request_action(self.agent_id, action, resource, metadata)

    def guarded(
        self,
        action: str,
        resource: str,
        perform: Callable[[], Any],
        metadata: Optional[dict] = None,
    ) -> Any:
        """Authorize then perform an action; raise if denied."""
        decision = self.request(action, resource, metadata)
        if not decision.approved:
            raise PraetorDenied(decision)

        if decision.capability:
            # Low-risk path: redeem the single-use token at the action boundary.
            ok = self.orchestrator.redeem_capability(decision.capability, self.agent_id, action, resource)
            if not ok:
                raise PraetorDenied(decision)

        return perform()
