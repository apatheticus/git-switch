"""Main application controller for Git-Switch.

This module provides the GitSwitchApp class which serves as the entry point
for the DearPyGui-based user interface.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import dearpygui.dearpygui as dpg

from src.ui.dialogs.password_dialog import show_password_dialog
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
        self._auth_complete = False

        logger.debug("GitSwitchApp initialized")

    def run(self) -> None:
        """Start the application main loop.

        Creates the DearPyGui context, viewport, and windows,
        then enters the main render loop until exit is requested.
        """
        logger.info("Starting Git-Switch application")

        try:
            self._setup_dearpygui()
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

    def _detect_and_display_current_profile(self) -> None:
        """Detect current git profile and update UI state.

        Called at startup after authentication to detect which profile
        matches the current git global configuration. If no profile matches,
        still displays the current git config in the header.
        """
        try:
            # First try to match against saved profiles
            detected_profile = self._profile_manager.detect_current_profile()
            if detected_profile:
                logger.info(
                    f"Detected current profile at startup: {detected_profile.name}"
                )
                # Store for header update after window is created
                self._detected_git_config = {
                    "name": detected_profile.name,
                    "email": detected_profile.git_email,
                    "organization": detected_profile.organization,
                    "is_profile": True,
                }
            else:
                # No matching profile - get raw git config to display
                git_config = self._profile_manager.get_current_git_config()
                if git_config:
                    current_name = git_config.get("user.name", "").strip()
                    current_email = git_config.get("user.email", "").strip()
                    if current_name or current_email:
                        logger.info(
                            f"No matching profile, showing git config: "
                            f"{current_name} <{current_email}>"
                        )
                        self._detected_git_config = {
                            "name": current_name or "(no name)",
                            "email": current_email or "(no email)",
                            "organization": None,
                            "is_profile": False,
                        }
                    else:
                        logger.debug("No git user configured")
                        self._detected_git_config = None
                else:
                    logger.debug("Could not read git configuration")
                    self._detected_git_config = None
        except Exception as e:
            logger.warning(f"Failed to detect current profile at startup: {e}")
            self._detected_git_config = None

    def _setup_main_window(self) -> None:
        """Build the main application window layout."""
        logger.debug("Creating main window")
        create_main_window(self._container)

        # Update header with detected git config
        if hasattr(self, "_detected_git_config") and self._detected_git_config:
            from src.ui.main_window import update_active_profile

            config = self._detected_git_config
            update_active_profile(
                name=config["name"],
                email=config["email"],
                organization=config.get("organization"),
                is_ready=True,
            )

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

    def _show_auth_dialog(self) -> None:
        """Show authentication dialog on startup.

        Checks if master password exists and shows appropriate dialog:
        - First-time: Create master password dialog
        - Subsequent: Unlock dialog
        """
        is_first_time = not self._session.has_master_password()
        logger.debug(f"Showing auth dialog (first_time={is_first_time})")

        show_password_dialog(
            is_first_time=is_first_time,
            on_submit=self._on_auth_submit,
            on_cancel=self._on_auth_cancel,
        )

    def _on_auth_submit(self, password: str) -> None:
        """Handle successful password submission.

        Args:
            password: The password entered by user.
        """
        try:
            if not self._session.has_master_password():
                # First-time setup
                self._session.setup_master_password(password)
                logger.info("Master password created successfully")
            elif not self._session.unlock(password):
                # Unlock existing session - failed
                logger.warning("Invalid password entered")
                self._show_auth_error("Invalid password. Please try again.")
                return

            # Authentication successful - detect current profile from git config
            self._detect_and_display_current_profile()

            # Create main window
            self._auth_complete = True
            self._setup_main_window()

            # Update tray menu
            if self._tray_icon is not None:
                self._tray_icon.update_menu()

            logger.info("Session unlocked successfully")

        except Exception as e:
            logger.exception("Authentication failed")
            self._show_auth_error(f"Authentication failed: {e}")

    def _on_auth_cancel(self) -> None:
        """Handle auth dialog cancellation."""
        if not self._auth_complete:
            # User cancelled without authenticating - exit app
            logger.info("Authentication cancelled, exiting")
            self._request_exit()

    def _show_auth_error(self, message: str) -> None:
        """Show authentication error and re-prompt.

        Args:
            message: Error message to display.
        """
        logger.warning(f"Auth error: {message}")
        # Re-show the dialog
        is_first_time = not self._session.has_master_password()
        show_password_dialog(
            is_first_time=is_first_time,
            on_submit=self._on_auth_submit,
            on_cancel=self._on_auth_cancel,
        )

    def _show_lock_overlay(self) -> None:
        """Display the session lock overlay dialog.

        Shows the password dialog for re-authentication after auto-lock.
        """
        logger.debug("Session locked, showing unlock dialog")
        show_password_dialog(
            is_first_time=False,
            on_submit=self._on_unlock_submit,
            on_cancel=None,  # Don't allow cancel when locked
        )

    def _on_unlock_submit(self, password: str) -> None:
        """Handle unlock password submission.

        Args:
            password: The password entered by user.
        """
        if self._session.unlock(password):
            logger.info("Session unlocked after auto-lock")
            # Refresh views
            from src.ui.views.profiles_view import refresh_profiles

            refresh_profiles()

            if self._tray_icon is not None:
                self._tray_icon.update_menu()
        else:
            logger.warning("Invalid password on unlock attempt")
            # Re-show dialog
            self._show_lock_overlay()

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

        # Show password dialog on startup
        self._show_auth_dialog()

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
