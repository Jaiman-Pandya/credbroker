"""Tool adapters: the only code that talks to real provider APIs."""

from credbroker.config import Settings
from credbroker.tools.base import TOOL_REGISTRY, ToolAdapter, get_tool, register_tool
from credbroker.tools.drive import DriveListFilesTool

register_tool(DriveListFilesTool())


def configure_tools(settings: Settings) -> None:
    """Apply settings to every registered tool. Call once at process startup."""
    for tool in TOOL_REGISTRY.values():
        tool.configure(settings)


__all__ = [
    "TOOL_REGISTRY",
    "ToolAdapter",
    "configure_tools",
    "get_tool",
    "register_tool",
    "DriveListFilesTool",
]
