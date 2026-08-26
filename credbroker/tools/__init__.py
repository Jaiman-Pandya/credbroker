"""Tool adapters: the only code that talks to real provider APIs."""

from credbroker.tools.base import TOOL_REGISTRY, ToolAdapter, get_tool, register_tool
from credbroker.tools.drive import DriveListFilesTool

register_tool(DriveListFilesTool())

__all__ = ["TOOL_REGISTRY", "ToolAdapter", "get_tool", "register_tool", "DriveListFilesTool"]
