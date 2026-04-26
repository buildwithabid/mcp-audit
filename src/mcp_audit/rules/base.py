from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Iterator

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


def iter_string_properties(schema: Any) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield `(name, prop_schema)` for each dict-shaped property in a JSON schema.

    Skips silently if the schema or its `properties` aren't dicts, so rules can
    walk untrusted server-supplied schemas without `isinstance` boilerplate.
    """
    if not isinstance(schema, dict):
        return
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return
    for name, prop in properties.items():
        if isinstance(prop, dict):
            yield name, prop
