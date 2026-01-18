"""Theme constants and creation for Git-Switch UI.

This module provides color constants, layout dimensions, and theme
creation functions for the DearPyGui-based user interface.
"""

from __future__ import annotations

from typing import Final

import dearpygui.dearpygui as dpg

# =============================================================================
# Color Constants (RGBA tuples for DearPyGui)
# =============================================================================

# Dark cyberpunk color palette
COLORS: Final[dict[str, tuple[int, int, int] | tuple[int, int, int, int]]] = {
    # Backgrounds
    "bg_dark": (15, 23, 42),  # #0F172A - Window background
    "bg_panel": (30, 41, 59),  # #1E293B - Panel/sidebar background
    "bg_card": (51, 65, 85),  # #334155 - Card background
    "bg_input": (71, 85, 105),  # #475569 - Input field background
    # Accents
    "accent_cyan": (0, 212, 255),  # #00D4FF - Primary accent
    "accent_glow": (0, 255, 255, 80),  # #00FFFF with alpha - Glow effect
    "accent_hover": (56, 189, 248),  # #38BDF8 - Lighter cyan for hover
    # Text
    "text_primary": (241, 245, 249),  # #F1F5F9 - Primary text
    "text_secondary": (148, 163, 184),  # #94A3B8 - Secondary text
    "text_disabled": (100, 116, 139),  # #64748B - Disabled text
    # Status indicators
    "success": (34, 197, 94),  # #22C55E - Success indicator
    "warning": (234, 179, 8),  # #EAB308 - Warning indicator
    "error": (239, 68, 68),  # #EF4444 - Error indicator
    # Borders and separators
    "border": (71, 85, 105),  # #475569 - Border color
    "separator": (51, 65, 85),  # #334155 - Separator line
}


# =============================================================================
# Layout Dimensions
# =============================================================================

# Application window
APP_WIDTH: Final[int] = 900
APP_HEIGHT: Final[int] = 600

# Layout sections
SIDEBAR_WIDTH: Final[int] = 200
HEADER_HEIGHT: Final[int] = 110
FOOTER_HEIGHT: Final[int] = 36

# Spacing and padding
PADDING_LARGE: Final[int] = 16
PADDING_MEDIUM: Final[int] = 12
PADDING_SMALL: Final[int] = 8

# Corner rounding
FRAME_ROUNDING: Final[int] = 4
BUTTON_ROUNDING: Final[int] = 4


# =============================================================================
# Element Tags (for DearPyGui identification)
# =============================================================================

TAGS: Final[dict[str, str]] = {
    # Windows
    "win": "gs_main_window",
    # Views (content areas)
    "view_profiles": "view_profiles",
    "view_repos": "view_repos",
    "view_settings": "view_settings",
    "view_import": "view_import",
    "content_stack": "content_stack",
    # Header elements
    "active_profile_card": "active_profile_card",
    "profile_name": "profile_name_text",
    "profile_email": "profile_email_text",
    "profile_org": "profile_org_text",
    "online_indicator": "online_indicator",
    # Footer status elements
    "status_ssh": "status_ssh",
    "status_gpg": "status_gpg",
    "status_scope": "status_scope",
    # Dialogs
    "dialog_lock": "dialog_lock",
    "dialog_password": "dialog_password",
    "dialog_confirm": "dialog_confirm",
}


# =============================================================================
# Theme Creation
# =============================================================================


def create_theme() -> int:
    """Create and return the dark cyberpunk theme.

    Returns:
        Theme tag ID for use with dpg.bind_theme().
    """
    with dpg.theme() as global_theme, dpg.theme_component(dpg.mvAll):
        # Window and panel backgrounds
        dpg.add_theme_color(
            dpg.mvThemeCol_WindowBg,
            COLORS["bg_dark"],
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_ChildBg,
            COLORS["bg_panel"],
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_PopupBg,
            COLORS["bg_panel"],
        )

        # Frame/input backgrounds
        dpg.add_theme_color(
            dpg.mvThemeCol_FrameBg,
            COLORS["bg_input"],
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_FrameBgHovered,
            COLORS["bg_card"],
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_FrameBgActive,
            COLORS["accent_cyan"],
        )

        # Button styling
        dpg.add_theme_color(
            dpg.mvThemeCol_Button,
            COLORS["bg_card"],
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_ButtonHovered,
            COLORS["accent_cyan"],
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_ButtonActive,
            COLORS["accent_hover"],
        )

        # Header styling
        dpg.add_theme_color(
            dpg.mvThemeCol_Header,
            COLORS["bg_card"],
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_HeaderHovered,
            COLORS["accent_cyan"],
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_HeaderActive,
            COLORS["accent_hover"],
        )

        # Text colors
        dpg.add_theme_color(
            dpg.mvThemeCol_Text,
            COLORS["text_primary"],
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_TextDisabled,
            COLORS["text_disabled"],
        )

        # Borders
        dpg.add_theme_color(
            dpg.mvThemeCol_Border,
            COLORS["border"],
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_Separator,
            COLORS["separator"],
        )

        # Scrollbar
        dpg.add_theme_color(
            dpg.mvThemeCol_ScrollbarBg,
            COLORS["bg_dark"],
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_ScrollbarGrab,
            COLORS["bg_card"],
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_ScrollbarGrabHovered,
            COLORS["accent_cyan"],
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_ScrollbarGrabActive,
            COLORS["accent_hover"],
        )

        # Title bar
        dpg.add_theme_color(
            dpg.mvThemeCol_TitleBg,
            COLORS["bg_dark"],
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_TitleBgActive,
            COLORS["bg_panel"],
        )

        # Tab styling
        dpg.add_theme_color(
            dpg.mvThemeCol_Tab,
            COLORS["bg_card"],
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_TabHovered,
            COLORS["accent_cyan"],
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_TabActive,
            COLORS["accent_cyan"],
        )

        # Checkbox/radio styling
        dpg.add_theme_color(
            dpg.mvThemeCol_CheckMark,
            COLORS["accent_cyan"],
        )

        # Slider styling
        dpg.add_theme_color(
            dpg.mvThemeCol_SliderGrab,
            COLORS["accent_cyan"],
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_SliderGrabActive,
            COLORS["accent_hover"],
        )

        # Style - rounding
        dpg.add_theme_style(
            dpg.mvStyleVar_FrameRounding,
            FRAME_ROUNDING,
        )
        dpg.add_theme_style(
            dpg.mvStyleVar_WindowRounding,
            FRAME_ROUNDING,
        )
        dpg.add_theme_style(
            dpg.mvStyleVar_ChildRounding,
            FRAME_ROUNDING,
        )
        dpg.add_theme_style(
            dpg.mvStyleVar_PopupRounding,
            FRAME_ROUNDING,
        )
        dpg.add_theme_style(
            dpg.mvStyleVar_ScrollbarRounding,
            FRAME_ROUNDING,
        )

        # Style - padding and spacing
        dpg.add_theme_style(
            dpg.mvStyleVar_WindowPadding,
            PADDING_MEDIUM,
            PADDING_MEDIUM,
        )
        dpg.add_theme_style(
            dpg.mvStyleVar_FramePadding,
            PADDING_SMALL,
            PADDING_SMALL,
        )
        dpg.add_theme_style(
            dpg.mvStyleVar_ItemSpacing,
            PADDING_SMALL,
            PADDING_SMALL,
        )

    return global_theme


def create_nav_button_theme() -> int:
    """Create theme for navigation buttons in the sidebar.

    Returns:
        Theme tag ID for navigation buttons.
    """
    with dpg.theme() as nav_theme, dpg.theme_component(dpg.mvButton):
        dpg.add_theme_color(
            dpg.mvThemeCol_Button,
            (0, 0, 0, 0),  # Transparent background
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_ButtonHovered,
            (*COLORS["accent_cyan"][:3], 40),  # Cyan with low alpha
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_ButtonActive,
            (*COLORS["accent_cyan"][:3], 80),  # Cyan with medium alpha
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_Text,
            COLORS["text_secondary"],
        )
    return nav_theme


def create_active_nav_button_theme() -> int:
    """Create theme for the currently active navigation button.

    Returns:
        Theme tag ID for active navigation button.
    """
    with dpg.theme() as active_theme, dpg.theme_component(dpg.mvButton):
        dpg.add_theme_color(
            dpg.mvThemeCol_Button,
            (*COLORS["accent_cyan"][:3], 60),
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_ButtonHovered,
            (*COLORS["accent_cyan"][:3], 80),
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_ButtonActive,
            (*COLORS["accent_cyan"][:3], 100),
        )
        dpg.add_theme_color(
            dpg.mvThemeCol_Text,
            COLORS["accent_cyan"],
        )
    return active_theme


def create_status_theme(status: str) -> int:
    """Create theme for status indicator text.

    Args:
        status: One of 'success', 'warning', 'error'.

    Returns:
        Theme tag ID for status text.
    """
    color = COLORS.get(status, COLORS["text_secondary"])

    with dpg.theme() as status_theme, dpg.theme_component(dpg.mvText):
        dpg.add_theme_color(
            dpg.mvThemeCol_Text,
            color,
        )
    return status_theme


__all__ = [
    "APP_HEIGHT",
    "APP_WIDTH",
    "BUTTON_ROUNDING",
    # Constants
    "COLORS",
    "FOOTER_HEIGHT",
    "FRAME_ROUNDING",
    "HEADER_HEIGHT",
    "PADDING_LARGE",
    "PADDING_MEDIUM",
    "PADDING_SMALL",
    "SIDEBAR_WIDTH",
    "TAGS",
    "create_active_nav_button_theme",
    "create_nav_button_theme",
    "create_status_theme",
    # Theme functions
    "create_theme",
]
