from __future__ import annotations

from abc import ABC, abstractmethod

from mcp_audit.models import Finding, ServerInfo, Severity


class Rule(ABC):
    """Base class for all rules.

    Subclasses must set the four class attributes below and implement `check`.
    Rules are pure inspection — `ServerInfo` is fully fetched before any rule runs.
    """

    id: str
    title: str
    severity: Severity
    description: str

    @abstractmethod
    def check(self, server_info: ServerInfo) -> list[Finding]:
        ...

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        for attr in ("id", "title", "severity", "description"):
            if not getattr(cls, attr, None):
                raise TypeError(f"{cls.__name__} must set class attribute `{attr}`")
