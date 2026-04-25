from __future__ import annotations

import importlib
import pkgutil

from mcp_audit.rules.base import Rule

_RULES: list[type[Rule]] = []


def _discover() -> list[type[Rule]]:
    if _RULES:
        return _RULES
    package = importlib.import_module(__name__)
    for mod_info in pkgutil.iter_modules(package.__path__):
        if mod_info.name in ("base", "__init__"):
            continue
        module = importlib.import_module(f"{__name__}.{mod_info.name}")
        for obj in vars(module).values():
            if (
                isinstance(obj, type)
                and issubclass(obj, Rule)
                and obj is not Rule
                and obj not in _RULES
            ):
                _RULES.append(obj)
    _RULES.sort(key=lambda c: c.id)
    return _RULES


def all_rules() -> list[Rule]:
    return [cls() for cls in _discover()]


def all_rule_classes() -> list[type[Rule]]:
    return list(_discover())
