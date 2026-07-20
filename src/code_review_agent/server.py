"""MCP server entry point."""

from __future__ import annotations

import asyncio
import logging
import sys

from mcp.server import Server
from mcp.server.stdio import stdio_server

from .tools import register_review_tools

logger = logging.getLogger("code-review-agent-mcp")


def create_server() -> Server:
    """Create and configure the MCP server.

    The list_tools and call_tool handlers are registered by
    register_review_tools() — we do not register a fallback here
    because MCP SDK overwrites earlier registrations with later ones.
    """
    server = Server("code-review-agent-mcp")
    register_review_tools(server)
    return server


async def run_server() -> None:
    """Run the MCP server with stdio transport."""
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    logger.info("Starting code-review-agent-mcp server")

    server = create_server()

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main() -> None:
    """CLI entry point."""
    asyncio.run(run_server())


if __name__ == "__main__":
    main()
