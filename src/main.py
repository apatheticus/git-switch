#!/usr/bin/env python3
"""Git-Switch Profile Manager - Application Entry Point.

This module serves as the main entry point for the Git-Switch application.
It initializes the service container, handles master password authentication,
and launches the main application window.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.services.container import ServiceContainer

# Setup logging before importing application modules
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments.

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        prog="git-switch",
        description="Git Profile Manager - Switch between Git/GitHub profiles easily",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--minimized",
        action="store_true",
        help="Start minimized to system tray",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="Git-Switch 1.0.0",
    )
    return parser.parse_args()


def setup_logging(debug: bool = False) -> None:
    """Configure application logging.

    Args:
        debug: Enable debug level logging.
    """
    level = logging.DEBUG if debug else logging.INFO
    logging.getLogger().setLevel(level)

    # Reduce noise from libraries
    logging.getLogger("dearpygui").setLevel(logging.WARNING)
    logging.getLogger("PIL").setLevel(logging.WARNING)
    logging.getLogger("paramiko").setLevel(logging.WARNING)

    if debug:
        logger.debug("Debug logging enabled")


def get_icon_path() -> Path | None:
    """Get the path to the application icon.

    Returns:
        Path to icon file or None if not found.
    """
    # Check various possible locations
    possible_paths = [
        Path(__file__).parent.parent / "assets" / "icons" / "app_icon.ico",
        Path(__file__).parent / "assets" / "icons" / "app_icon.ico",
        Path("assets") / "icons" / "app_icon.ico",
    ]

    for path in possible_paths:
        if path.exists():
            return path

    logger.debug("Application icon not found")
    return None


def create_service_container() -> ServiceContainer:
    """Create and initialize the service container.

    Returns:
        Configured ServiceContainer instance.
    """
    from src.services.container import create_container

    logger.debug("Creating service container")
    container = create_container()
    logger.debug("Service container created")
    return container


def main() -> int:
    """Main application entry point.

    Returns:
        Exit code (0 for success, non-zero for errors).
    """
    # Parse command line arguments
    args = parse_args()

    # Configure logging
    setup_logging(debug=args.debug)

    logger.info("Starting Git-Switch Profile Manager")

    try:
        # Get icon path
        icon_path = get_icon_path()

        # Create service container with all dependencies
        container = create_service_container()

        # Import app module here to avoid circular imports
        from src.ui.app import GitSwitchApp

        # Create and run application
        app = GitSwitchApp(container, icon_path=icon_path)
        app.run()

        logger.info("Git-Switch exited normally")
        return 0

    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, shutting down")
        return 0

    except Exception:
        logger.exception("Fatal error in Git-Switch")
        return 1


if __name__ == "__main__":
    sys.exit(main())
