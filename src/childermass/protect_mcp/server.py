"""
Childermass UniFi Protect MCP Server

Custom UniFi Protect MCP server for Claude Code / OpenCode.
All communication is local – direct HTTPS to the NVR on the LAN.

Security: All tool responses go through error sanitization so that
NVR credentials, IP addresses, or cookies are never leaked to the LLM.

Run with: python -m childermass.protect_mcp.server
"""

from dataclasses import asdict

from mcp.server.fastmcp import FastMCP

from . import client
from .security import SecurityError, sanitize_error_message

# Create FastMCP server
mcp = FastMCP("childermass-protect")


# ---------------------------------------------------------------------------
# Helper: safe tool wrapper
# ---------------------------------------------------------------------------


def _safe_call(func, *args, **kwargs):
    """Execute a client call with error sanitization."""
    try:
        return func(*args, **kwargs)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Camera tools
# ---------------------------------------------------------------------------


@mcp.tool()
def protect_list_cameras() -> list[dict] | dict:
    """
    List all UniFi Protect cameras with their current status.

    Returns:
        List of cameras with id, name, model, state, recording status,
        motion detection, doorbell info, and smart detection capabilities.
    """
    try:
        cameras = client.list_cameras()
        return [asdict(cam) for cam in cameras]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def protect_get_camera_snapshot(
    camera_id: str,
    width: int = 640,
    height: int = 360,
) -> dict:
    """
    Get a live snapshot image from a camera.

    Use protect_list_cameras first to get camera IDs.

    Args:
        camera_id: Camera ID (24-char hex string from protect_list_cameras)
        width: Image width in pixels (default: 640, max: 3840)
        height: Image height in pixels (default: 360, max: 3840)

    Returns:
        Dict with base64-encoded JPEG image, camera name, and dimensions
    """
    try:
        image_b64 = client.get_camera_snapshot(
            camera_id=camera_id,
            width=width,
            height=height,
        )
        camera_name = client._session.get_camera_name(camera_id)
        return {
            "camera_id": camera_id,
            "camera_name": camera_name,
            "width": width,
            "height": height,
            "format": "jpeg",
            "image_base64": image_b64,
        }
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Event tools
# ---------------------------------------------------------------------------


@mcp.tool()
def protect_list_events(
    hours_back: int = 24,
    camera_id: str = "",
    event_types: str = "",
    smart_detect_types: str = "",
    max_results: int = 30,
) -> list[dict] | dict:
    """
    List detected events (motion, smart detection, doorbell rings) from UniFi Protect.

    Args:
        hours_back: How many hours back to search (default: 24, max: 168 = 7 days)
        camera_id: Optional camera ID to filter events (from protect_list_cameras)
        event_types: Comma-separated event types to filter.
            Options: "motion", "smartDetectZone", "ring"
        smart_detect_types: Comma-separated smart detection types to filter.
            Options: "person", "vehicle", "package", "animal", "face", "licensePlate"
        max_results: Maximum events to return (default: 30, max: 100)

    Returns:
        List of events with camera, type, time, score, smart detection info, and metadata
    """
    try:
        import time

        now_ms = int(time.time() * 1000)
        start_ms = now_ms - (hours_back * 60 * 60 * 1000)

        types_list = (
            [t.strip() for t in event_types.split(",") if t.strip()]
            if event_types
            else None
        )
        smart_list = (
            [t.strip() for t in smart_detect_types.split(",") if t.strip()]
            if smart_detect_types
            else None
        )

        events = client.list_events(
            start_ms=start_ms,
            end_ms=now_ms,
            camera_id=camera_id or None,
            event_types=types_list,
            smart_detect_types=smart_list,
            max_results=max_results,
        )
        return [asdict(ev) for ev in events]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def protect_get_event_thumbnail(event_id: str) -> dict:
    """
    Get the thumbnail image for a specific event.

    Use protect_list_events first to get event IDs.

    Args:
        event_id: Event ID (24-char hex string from protect_list_events)

    Returns:
        Dict with base64-encoded JPEG thumbnail image
    """
    try:
        image_b64 = client.get_event_thumbnail(event_id)
        return {
            "event_id": event_id,
            "format": "jpeg",
            "image_base64": image_b64,
        }
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Sensor tools
# ---------------------------------------------------------------------------


@mcp.tool()
def protect_list_sensors() -> list[dict] | dict:
    """
    List all UniFi Protect sensors with current readings.

    Returns sensor data including temperature (°C), humidity (%),
    light level (lux), motion detection, and door/window contact status.
    Useful for checking home environment conditions.

    Returns:
        List of sensors with id, name, readings, battery status, and alerts
    """
    try:
        sensors = client.list_sensors()
        return [asdict(s) for s in sensors]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Light tools
# ---------------------------------------------------------------------------


@mcp.tool()
def protect_list_lights() -> list[dict] | dict:
    """
    List all UniFi Protect-managed lights (Floodlights, etc.).

    Returns:
        List of lights with id, name, on/off state, darkness, and motion status
    """
    try:
        lights = client.list_lights()
        return [asdict(light) for light in lights]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def protect_toggle_light(light_id: str, turn_on: bool = True) -> dict:
    """
    Turn a UniFi Protect light on or off.

    Use protect_list_lights first to get light IDs.

    Args:
        light_id: Light ID (24-char hex string from protect_list_lights)
        turn_on: True to turn on, False to turn off (default: True)

    Returns:
        Updated light state
    """
    try:
        light = client.toggle_light(light_id, on=turn_on)
        return asdict(light)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Doorbell tools
# ---------------------------------------------------------------------------


@mcp.tool()
def protect_check_doorbell() -> list[dict] | dict:
    """
    Check doorbell status – last ring time, LCD message, and capabilities.

    Returns:
        List of doorbells with ring info and smart detection capabilities
    """
    try:
        doorbells = client.list_doorbells()
        if not doorbells:
            return {"message": "No doorbell cameras found in the system"}
        return [asdict(db) for db in doorbells]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# System / NVR tools
# ---------------------------------------------------------------------------


@mcp.tool()
def protect_get_system_status() -> dict:
    """
    Get comprehensive UniFi Protect system status.

    Returns NVR health, storage usage, camera states, sensor readings,
    light states, and any active issues/alerts. Ideal for daily briefings
    and quick system health checks.

    Returns:
        Combined system status with NVR info, cameras, sensors, lights, and issues list
    """
    try:
        return client.get_system_status()
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def protect_get_recent_activity(hours: int = 24) -> dict:
    """
    Get a summary of recent security activity across all cameras.

    Aggregates events into a concise overview: total motion events,
    smart detections by type (person, vehicle, package, animal),
    doorbell rings, and per-camera activity breakdown.

    Great for evening reviews ("what happened at home today?").

    Args:
        hours: How many hours back to look (default: 24, max: 168)

    Returns:
        Activity summary with event counts, smart detection breakdown,
        and per-camera activity
    """
    try:
        summary = client.get_recent_activity(hours=hours)
        return asdict(summary)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Server entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
