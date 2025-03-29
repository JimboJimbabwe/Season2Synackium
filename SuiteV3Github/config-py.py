"""
Configuration settings for the Security Testing Directory Navigator
"""

# Color scheme for risk levels
RISK_COLORS = {
    "high": "#ff5555",    # Red
    "medium": "#ffaa55",  # Orange
    "low": "#55aa55",     # Green
    "unknown": "#777777"  # Gray
}

# Theme colors
THEME_COLORS = {
    "header_bg": "#2b2b2b",
    "list_header_bg": "#1f538d",
    "hover_bg": "#1e3046",
    "row_alternate_bg": ("#f0f0f0", "#2a2a2a")
}

# Application settings
APP_TITLE = "Security Testing Directory Navigator"
APP_GEOMETRY = "1280x768"
APP_MIN_SIZE = (800, 600)
