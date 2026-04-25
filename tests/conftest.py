from __future__ import annotations

import pytest

from mcp_audit.models import (
    PromptArgument,
    PromptInfo,
    ResourceInfo,
    ServerInfo,
    Target,
    ToolInfo,
)


def make_server(
    *,
    target_type: str = "stdio",
    target_value: str = "python server.py",
    tools: list[ToolInfo] | None = None,
    resources: list[ResourceInfo] | None = None,
    prompts: list[PromptInfo] | None = None,
    metadata: dict | None = None,
) -> ServerInfo:
    return ServerInfo(
        target=Target(type=target_type, value=target_value),  # type: ignore[arg-type]
        tools=tools or [],
        resources=resources or [],
        prompts=prompts or [],
        server_metadata=metadata or {},
    )


@pytest.fixture
def empty_server() -> ServerInfo:
    return make_server()


@pytest.fixture
def make_server_fixture():
    return make_server


@pytest.fixture
def tool_factory():
    def _make(
        name: str = "tool",
        description: str | None = None,
        input_schema: dict | None = None,
    ) -> ToolInfo:
        return ToolInfo(
            name=name,
            description=description,
            input_schema=input_schema or {"type": "object", "properties": {}},
        )
    return _make


@pytest.fixture
def resource_factory():
    def _make(uri: str, description: str | None = None) -> ResourceInfo:
        return ResourceInfo(uri=uri, name=uri, description=description)
    return _make


@pytest.fixture
def prompt_factory():
    def _make(
        name: str = "p",
        description: str | None = None,
        args: list[PromptArgument] | None = None,
    ) -> PromptInfo:
        return PromptInfo(name=name, description=description, arguments=args or [])
    return _make
