"""Tool adapters: the only code that talks to real provider APIs."""

from credbroker.tools.base import TOOL_REGISTRY, ToolAdapter, get_tool, register_tool

__all__ = ["TOOL_REGISTRY", "ToolAdapter", "get_tool", "register_tool"]
