"""Middleware package for Wazuh MCP server."""
from .tool_middleware import ToolMiddleware

__all__ = ["ToolMiddleware"]
