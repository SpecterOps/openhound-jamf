"""Shared utilities for JAMF model validators."""

NO_SITE_ID = -1
# The Jamf Pro API (v1) returns site.id as a string, unlike the Classic API which uses an int.
NO_SITE_ID_STR = str(NO_SITE_ID)
_SENTINEL_SITE = {"id": NO_SITE_ID}


def normalize_site(v):
    """Coerce a raw site value into a valid site dict.

    Returns the sentinel ``{"id": -1}`` when the value is ``None`` or already
    the sentinel, and passes all other values through unchanged so Pydantic can
    validate them normally.
    """
    if v is None:
        return _SENTINEL_SITE
    if isinstance(v, dict) and v.get("id") == NO_SITE_ID:
        return _SENTINEL_SITE
    return v
