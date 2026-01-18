"""Main application controller for Git-Switch.

This module provides the GitSwitchApp class which serves as the entry point
for the DearPyGui-based user interface.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import dearpygui.dearpygui as dpg

from src.ui.main_window import create_main_window
from src.ui.system_tray import SystemTrayIcon
from src.ui.theme import APP_HEIGHT, APP_WIDTH, create_theme

if TYPE_CHECKING:
    from pathlib import Path

    from src.services.container import ServiceContainer

logger = logging.getLogger(__name__)

# Application title
APP_TITLE = "Git-Switch Profile Manager"

# Viewport chrome (title bar, borders) added to content size
VIEWPORT_CHROME_WIDTH = 16
VIEWPORT_CHROME_HEIGHT = 39


class GitSwitchApp:
    """Main application controller for Git-Switch.

    This class manages:
    - DearPyGui context and viewport creation
    - Theme application
    - Main window construction
    - System tray integration
    - Session lock/unlock handling
    - Idle activity tracking

    Attributes:
        _container: Service container for dependency injection.
        _session: Session manager reference.
        _profile_manager: Profile manager reference.
        _tray_icon: System tray icon instance.
        _is_running: Whether the application is currently running.
    """

    def __init__(
        self,
        container: ServiceContainer,
        icon_path: Path | None = None,
    ) -> None:
        """Initialize the Git-Switch application.

        Args:
            container: Service container with all dependencies.
            icon_path: Optional path to application icon file.
        """
        self._container = container
        self._session = container.session_manager
        self._profile_manager = container.profile_manager
        self._icon_path = icon_path
        self._tray_icon: SystemTrayIcon | None = None
        self._is_running = False
        self._theme_id: int | None = None
        self._last_mouse_pos: tuple[float, float] = (0.0, 0.0)

        logger.debug("GitSwitchApp initialized")

    def run(self) -> None:
        """Start the application main loop.

        Creates the DearPyGui context, viewport, and windows,
        then enters the main render loop until exit is requested.
        """
        logger.info("Starting Git-Switch application")

        try:
            self._setup_dearpygui()
            self._setup_main_window()
            self._setup_session_callbacks()
            self._setup_system_tray()
            self._run_main_loop()
        except Exception:
            logger.exception("Fatal error in application")
            raise
        finally:
            self._cleanup()

    def _setup_dearpygui(self) -> None:
        """Initialize DearPyGui context and viewport."""
        logger.debug("Creating DearPyGui context")
        dpg.create_context()

        # Create and apply theme
        self._theme_id = create_theme()
        dpg.bind_theme(self._theme_id)

        # Create viewport (main OS window)
        dpg.create_viewport(
            title=APP_TITLE,
            width=APP_WIDTH + VIEWPORT_CHROME_WIDTH,
            height=APP_HEIGHT + VIEWPORT_CHROME_HEIGHT,
            resizable=False,
            decorated=True,
            small_icon=str(self._icon_path) if self._icon_path else "",
            large_icon=str(self._icon_path) if self._icon_path else "",
        )

        logger.debug(f"Viewport created: {APP_WIDTH}x{APP_HEIGHT}")

    def _setup_main_window(self) -> None:
        """Build the main application window layout."""
        logger.debug("Creating main window")
        create_main_window(self._container)

    def _setup_session_callbacks(self) -> None:
        """Register callbacks for session events."""
        logger.debug("Setting up session callbacks")

        # Register lock callback
        self._session.set_lock_callback(self._on_session_locked)

        # Set up frame callback for idle tracking
        dpg.set_frame_callback(1, self._on_frame)

    def _on_frame(self) -> None:
        """Frame callback for activity tracking.

        Called once per frame, resets the session idle timer
        when user activity is detected. Tracks mouse movement,
        mouse clicks, and keyboard activity.
        """
        activity_detected = False

        # Check for mouse click activity
        if (
            dpg.is_mouse_button_down(dpg.mvMouseButton_Left)
            or dpg.is_mouse_button_down(dpg.mvMouseButton_Right)
            or dpg.is_mouse_button_down(dpg.mvMouseButton_Middle)
        ):
            activity_detected = True

        # Check for keyboard activity - common keys
        keys_to_check = [
            dpg.mvKey_Return,
            dpg.mvKey_Escape,
            dpg.mvKey_Tab,
            dpg.mvKey_Spacebar,
            dpg.mvKey_Back,
            dpg.mvKey_Delete,
            dpg.mvKey_Up,
            dpg.mvKey_Down,
            dpg.mvKey_Left,
            dpg.mvKey_Right,
        ]
        for key in keys_to_check:
            if dpg.is_key_down(key):
                activity_detected = True
                break

        # Check for mouse movement by comparing position
        if not activity_detected:
            mouse_pos = dpg.get_mouse_pos()
            if hasattr(self, "_last_mouse_pos") and mouse_pos != self._last_mouse_pos:
                activity_detected = True
            self._last_mouse_pos = mouse_pos

        # Reset idle timer on any activity
        if activity_detected:
            self._session.reset_idle_timer()

        # Re-register for next frame
        dpg.set_frame_callback(dpg.get_frame_count() + 1, self._on_frame)

    def _on_session_locked(self) -> None:
        """Handle session auto-lock event.

        Called when the session manager triggers an auto-lock
        due to inactivity timeout.
        """
        logger.info("Session locked, showing password dialog")
        self._show_lock_overlay()

        # Update tray menu if available
        if self._tray_icon is not None:
            self._tray_icon.update_menu()

    def _show_lock_overlay(self) -> None:
        """Display the session lock overlay dialog.

        Note: Full implementation in T097 (dialogs).
        This is a placeholder that will be replaced.
        """
        # TODO: Implement full lock dialog in T097
        logger.debug("Lock overlay requested (placeholder)")

    def _setup_system_tray(self) -> None:
        """Initialize and start the system tray icon."""
        logger.debug("Setting up system tray icon")

        self._tray_icon = SystemTrayIcon(
            session_manager=self._session,
            profile_manager=self._profile_manager,
            icon_path=self._icon_path,
            on_restore=self._on_restore_from_tray,
            on_exit=self._on_exit_from_tray,
        )

        self._tray_icon.start()

    def _on_restore_from_tray(self) -> None:
        """Restore the application window from system tray."""
        logger.debug("Restoring window from tray")

        try:
            # Show and focus the viewport
            dpg.show_viewport()
            dpg.focus_item(dpg.get_active_window())
        except Exception as e:
            logger.warning(f"Failed to restore window: {e}")

    def _on_exit_from_tray(self) -> None:
        """Handle exit request from system tray menu."""
        logger.info("Exit requested from system tray")
        self._request_exit()

    def _request_exit(self) -> None:
        """Request application exit."""
        self._is_running = False
        dpg.stop_dearpygui()

    def _run_main_loop(self) -> None:
        """Run the DearPyGui main render loop."""
        logger.debug("Starting main render loop")

        self._is_running = True

        # Setup and show viewport
        dpg.setup_dearpygui()
        dpg.show_viewport()

        # Center viewport on screen
        self._center_viewport()

        # Main loop
        while dpg.is_dearpygui_running() and self._is_running:
            dpg.render_dearpygui_frame()

        logger.debug("Main render loop ended")

    def _center_viewport(self) -> None:
        """Center the viewport on the primary monitor."""
        try:
            # Get screen dimensions (platform-specific)
            import ctypes

            user32 = ctypes.windll.user32
            screen_width = user32.GetSystemMetrics(0)
            screen_height = user32.GetSystemMetrics(1)

            viewport_width = APP_WIDTH + VIEWPORT_CHROME_WIDTH
            viewport_height = APP_HEIGHT + VIEWPORT_CHROME_HEIGHT

            x = (screen_width - viewport_width) // 2
            y = (screen_height - viewport_height) // 2

            dpg.set_viewport_pos([x, y])
            logger.debug(f"Viewport centered at ({x}, {y})")

        except Exception as e:
            logger.warning(f"Failed to center viewport: {e}")

    def _cleanup(self) -> None:
        """Clean up resources on application exit."""
        logger.info("Cleaning up application resources")

        # Stop system tray
        if self._tray_icon is not None:
            try:
                self._tray_icon.stop()
            except Exception as e:
                logger.warning(f"Error stopping tray icon: {e}")

        # Destroy DearPyGui context
        try:
            dpg.destroy_context()
        except Exception as e:
            logger.warning(f"Error destroying DearPyGui context: {e}")

        logger.info("Application cleanup complete")


def run_application(container: ServiceContainer, icon_path: Path | None = None) -> None:
    """Convenience function to run the Git-Switch application.

    Args:
        container: Service container with all dependencies.
        icon_path: Optional path to application icon file.
    """
    app = GitSwitchApp(container, icon_path)
    app.run()


__all__ = [
    "GitSwitchApp",
    "run_application",
]
