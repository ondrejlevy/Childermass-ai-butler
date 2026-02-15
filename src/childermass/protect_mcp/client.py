"""
UniFi Protect API Client Wrapper

Provides a clean interface for UniFi Protect NVR operations with integrated security.
All communication is local – direct HTTPS to the NVR on the LAN.

Security features:
- Input validation on all public functions
- Rate limiting per operation type
- Audit logging for state-changing operations
- Error message sanitization to prevent credential leaks
- Session auto-refresh on 401

API reference: https://developer.ui.com/protect/v6.2.88/
"""

import base64
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
import urllib3

from .auth import get_credentials, get_nvr_url, load_config, verify_ssl
from .security import (
    SecurityError,
    audit_log,
    rate_limiter,
    validate_camera_id,
    validate_event_id,
    validate_event_types,
    validate_hours,
    validate_light_id,
    validate_max_results,
    validate_smart_detect_types,
    validate_snapshot_dimensions,
    validate_time_range,
)


# Suppress InsecureRequestWarning for self-signed NVR certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


@dataclass
class Camera:
    """Camera device info."""

    id: str
    name: str
    type: str
    model: str
    state: str  # CONNECTED, DISCONNECTED, etc.
    is_recording: bool
    is_motion_detected: bool
    last_motion: str | None  # ISO 8601
    is_doorbell: bool
    last_ring: str | None  # ISO 8601, doorbells only
    has_package_camera: bool
    smart_detect_types: list[str]
    mic_enabled: bool
    status_light_on: bool
    hdr_mode: bool
    channels: list[dict]  # stream channel info


@dataclass
class Event:
    """Detected event."""

    id: str
    camera_name: str
    camera_id: str
    type: str  # motion, smartDetectZone, ring, etc.
    start: str  # ISO 8601
    end: str | None  # ISO 8601
    score: int
    smart_detect_types: list[str]
    thumbnail_id: str | None
    metadata: dict


@dataclass
class Sensor:
    """Sensor device (UP Sense, etc.)."""

    id: str
    name: str
    model: str
    state: str
    temperature: float | None  # °C
    humidity: float | None  # %
    light_level: float | None  # lux
    is_motion_detected: bool
    is_opened: bool  # door/window contact
    battery_percent: int | None
    alarm_triggered_at: str | None


@dataclass
class Light:
    """Light device (Floodlight, etc.)."""

    id: str
    name: str
    model: str
    state: str
    is_on: bool
    is_dark: bool
    is_motion_detected: bool
    last_motion: str | None
    led_level: int
    pir_sensitivity: int


@dataclass
class Doorbell:
    """Doorbell-specific info (derived from Camera)."""

    id: str
    name: str
    model: str
    state: str
    last_ring: str | None
    lcd_message: str | None
    has_package_camera: bool
    smart_detect_types: list[str]


@dataclass
class NvrInfo:
    """NVR system info."""

    name: str
    version: str
    firmware_version: str
    uptime_seconds: int
    uptime_human: str
    storage_used_bytes: int
    storage_total_bytes: int
    storage_used_percent: float
    recording_retention_days: int
    camera_count: int
    sensor_count: int
    light_count: int
    is_connected_to_cloud: bool


@dataclass
class ActivitySummary:
    """Activity summary for a time period."""

    period_hours: int
    total_events: int
    motion_events: int
    smart_detections: dict[str, int]  # type -> count
    ring_events: int
    cameras_with_activity: list[dict]  # [{name, event_count, last_event}]
    sensor_events: int


# ---------------------------------------------------------------------------
# Session Management
# ---------------------------------------------------------------------------


class _ProtectSession:
    """
    Manages authenticated HTTP session to the NVR.

    Handles login, CSRF tokens, cookies, and auto-refresh.
    """

    def __init__(self) -> None:
        self._client: httpx.Client | None = None
        self._csrf_token: str = ""
        self._base_url: str = ""
        self._last_login: float = 0
        self._bootstrap_cache: dict | None = None
        self._bootstrap_time: float = 0
        self._camera_names: dict[str, str] = {}  # id -> name cache

    def _ensure_client(self) -> httpx.Client:
        """Get or create the HTTP client."""
        if self._client is None:
            config = load_config()
            if config is None:
                msg = (
                    "NVR not configured. Run setup first:\n"
                    "  python -m childermass.protect_mcp.auth --setup"
                )
                raise RuntimeError(msg)

            self._base_url = get_nvr_url(config)
            ssl = verify_ssl(config)

            self._client = httpx.Client(
                verify=ssl,
                timeout=30.0,
                follow_redirects=True,
            )

        return self._client

    def _login(self) -> None:
        """Authenticate with the NVR and store session."""
        client = self._ensure_client()
        config = load_config()
        username, password = get_credentials(config)

        # Step 1: Get initial CSRF token
        try:
            resp = client.get(self._base_url)
            self._csrf_token = resp.headers.get("x-csrf-token", "")
        except httpx.ConnectError:
            msg = "Cannot connect to NVR. Check that the NVR is reachable."
            raise RuntimeError(msg)

        # Step 2: Login
        login_resp = client.post(
            f"{self._base_url}/api/auth/login",
            json={
                "username": username,
                "password": password,
                "rememberMe": True,
                "token": "",
            },
            headers={"x-csrf-token": self._csrf_token},
        )

        if login_resp.status_code == 401:
            msg = "NVR authentication failed – invalid username or password"
            raise SecurityError(msg)
        if login_resp.status_code != 200:
            msg = f"NVR login failed with HTTP {login_resp.status_code}"
            raise RuntimeError(msg)

        # Step 3: Extract updated CSRF token
        self._csrf_token = login_resp.headers.get(
            "x-updated-csrf-token",
            login_resp.headers.get("x-csrf-token", self._csrf_token),
        )
        self._last_login = time.monotonic()

        logger.info("Authenticated with NVR at %s", self._base_url)

    def _ensure_authenticated(self) -> None:
        """Ensure we have an active session, login if needed."""
        if self._last_login == 0:
            self._login()

    def request(
        self,
        method: str,
        path: str,
        **kwargs,
    ) -> httpx.Response:
        """
        Make an authenticated request to the Protect API.

        Auto-retries once on 401 (session expired).
        """
        self._ensure_authenticated()
        client = self._ensure_client()

        url = f"{self._base_url}{path}"
        headers = kwargs.pop("headers", {})
        headers["x-csrf-token"] = self._csrf_token

        resp = client.request(method, url, headers=headers, **kwargs)

        # Auto re-login on 401
        if resp.status_code == 401:
            logger.info("Session expired, re-authenticating...")
            self._login()
            headers["x-csrf-token"] = self._csrf_token
            resp = client.request(method, url, headers=headers, **kwargs)

        return resp

    def get(self, path: str, **kwargs) -> httpx.Response:
        """GET request."""
        return self.request("GET", path, **kwargs)

    def patch(self, path: str, **kwargs) -> httpx.Response:
        """PATCH request."""
        return self.request("PATCH", path, **kwargs)

    def get_json(self, path: str, **kwargs) -> dict | list:
        """GET request that returns parsed JSON."""
        resp = self.get(path, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def get_bootstrap(self, force_refresh: bool = False) -> dict:
        """
        Get bootstrap data (cached for 60 seconds).

        Bootstrap contains the complete system state.
        """
        now = time.monotonic()
        if (
            not force_refresh
            and self._bootstrap_cache is not None
            and (now - self._bootstrap_time) < 60
        ):
            return self._bootstrap_cache

        rate_limiter.check("bootstrap")

        raw = self.get_json("/proxy/protect/api/bootstrap")
        if not isinstance(raw, dict):
            msg = "Unexpected bootstrap response format"
            raise RuntimeError(msg)
        self._bootstrap_cache = raw
        self._bootstrap_time = now

        # Rebuild camera name cache
        self._camera_names = {}
        for cam in raw.get("cameras", []):
            self._camera_names[cam["id"]] = cam.get("name", cam["id"])

        return raw

    def get_camera_name(self, camera_id: str) -> str:
        """Resolve camera ID to name (from bootstrap cache)."""
        if not self._camera_names:
            self.get_bootstrap()
        return self._camera_names.get(camera_id, camera_id)

    def close(self) -> None:
        """Close the HTTP session."""
        if self._client:
            self._client.close()
            self._client = None
            self._last_login = 0


# Module-level session singleton
_session = _ProtectSession()


# ---------------------------------------------------------------------------
# Helper: timestamp formatting
# ---------------------------------------------------------------------------


def _ts_to_iso(ts_ms: int | float | None) -> str | None:
    """Convert Unix ms timestamp to ISO 8601 string."""
    if not ts_ms:
        return None
    try:
        dt = datetime.fromtimestamp(ts_ms / 1000, tz=UTC)
        return dt.isoformat()
    except (ValueError, OSError):
        return None


def _format_uptime(seconds: int) -> str:
    """Format seconds into human-readable uptime."""
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)

    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    return " ".join(parts) or "0m"


# ---------------------------------------------------------------------------
# Camera Operations
# ---------------------------------------------------------------------------


def list_cameras() -> list[Camera]:
    """
    List all cameras with their current status.

    Returns list of Camera dataclasses.
    """
    rate_limiter.check("read")

    bootstrap = _session.get_bootstrap()
    cameras = []

    for cam in bootstrap.get("cameras", []):
        feature_flags = cam.get("featureFlags", {})
        smart_settings = cam.get("smartDetectSettings", {})
        channels = cam.get("channels", [])

        cameras.append(
            Camera(
                id=cam["id"],
                name=cam.get("name", "Unknown"),
                type=cam.get("type", "Unknown"),
                model=cam.get("marketName", cam.get("type", "Unknown")),
                state=cam.get("state", "UNKNOWN"),
                is_recording=cam.get("isRecording", False),
                is_motion_detected=cam.get("isMotionDetected", False),
                last_motion=_ts_to_iso(cam.get("lastMotion")),
                is_doorbell=feature_flags.get("isDoorbell", False),
                last_ring=_ts_to_iso(cam.get("lastRing")),
                has_package_camera=feature_flags.get("hasPackageCamera", False),
                smart_detect_types=smart_settings.get("objectTypes", []),
                mic_enabled=cam.get("isMicEnabled", False),
                status_light_on=cam.get("ledSettings", {}).get("isEnabled", False),
                hdr_mode=cam.get("hdrMode", False),
                channels=[
                    {
                        "id": ch.get("id"),
                        "name": ch.get("name", ""),
                        "width": ch.get("width"),
                        "height": ch.get("height"),
                        "fps": ch.get("fps"),
                        "is_rtsp_enabled": ch.get("isRtspEnabled", False),
                    }
                    for ch in channels[:3]  # high, medium, low
                ],
            )
        )

    audit_log("list_cameras", details={"count": len(cameras)})
    return cameras


def get_camera(camera_id: str) -> Camera:
    """Get details for a specific camera."""
    camera_id = validate_camera_id(camera_id)
    rate_limiter.check("read")

    cameras = list_cameras()
    for cam in cameras:
        if cam.id == camera_id:
            return cam

    msg = f"Camera not found: {camera_id}"
    raise SecurityError(msg)


def get_camera_snapshot(
    camera_id: str,
    width: int | None = None,
    height: int | None = None,
) -> str:
    """
    Get a live snapshot from a camera.

    Returns base64-encoded JPEG image.
    """
    camera_id = validate_camera_id(camera_id)
    w, h = validate_snapshot_dimensions(width, height)
    rate_limiter.check("snapshot")

    resp = _session.get(
        f"/proxy/protect/api/cameras/{camera_id}/snapshot",
        params={"w": w, "h": h},
    )
    resp.raise_for_status()

    encoded = base64.b64encode(resp.content).decode("ascii")

    audit_log(
        "get_snapshot",
        details={
            "camera_id": camera_id,
            "camera_name": _session.get_camera_name(camera_id),
            "dimensions": f"{w}x{h}",
            "size_bytes": len(resp.content),
        },
    )

    return encoded


# ---------------------------------------------------------------------------
# Event Operations
# ---------------------------------------------------------------------------


def list_events(
    start_ms: int | None = None,
    end_ms: int | None = None,
    camera_id: str | None = None,
    event_types: list[str] | None = None,
    smart_detect_types: list[str] | None = None,
    max_results: int = 30,
) -> list[Event]:
    """
    List detected events within a time range.

    Args:
        start_ms: Start time (Unix ms). Default: 24 hours ago.
        end_ms: End time (Unix ms). Default: now.
        camera_id: Filter by camera ID.
        event_types: Filter by event types (motion, smartDetectZone, ring).
        smart_detect_types: Filter by smart detection types (person, vehicle, etc.)
        max_results: Maximum events to return (default 30, max 100).
    """
    # Defaults: last 24 hours
    now_ms = int(time.time() * 1000)
    if end_ms is None:
        end_ms = now_ms
    if start_ms is None:
        start_ms = now_ms - (24 * 60 * 60 * 1000)

    start_ms, end_ms = validate_time_range(start_ms, end_ms)
    max_results = validate_max_results(max_results)
    event_types = validate_event_types(event_types)
    smart_detect_types_validated = validate_smart_detect_types(smart_detect_types)

    if camera_id:
        camera_id = validate_camera_id(camera_id)

    rate_limiter.check("events")

    params: dict = {"start": start_ms, "end": end_ms}
    if event_types:
        params["types"] = event_types
    if camera_id:
        params["cameras"] = camera_id

    raw_events = _session.get_json(
        "/proxy/protect/api/events",
        params=params,
    )

    if not isinstance(raw_events, list):
        raw_events = []

    events = []
    for ev in raw_events:
        ev_smart_types = ev.get("smartDetectTypes", [])

        # Apply smart detect type filter client-side
        if smart_detect_types_validated:
            if not any(t in ev_smart_types for t in smart_detect_types_validated):
                continue

        events.append(
            Event(
                id=ev["id"],
                camera_name=_session.get_camera_name(ev.get("camera", "")),
                camera_id=ev.get("camera", ""),
                type=ev.get("type", "unknown"),
                start=_ts_to_iso(ev.get("start")) or "",
                end=_ts_to_iso(ev.get("end")),
                score=ev.get("score", 0),
                smart_detect_types=ev_smart_types,
                thumbnail_id=ev.get("thumbnail"),
                metadata=_extract_event_metadata(ev),
            )
        )

        if len(events) >= max_results:
            break

    audit_log(
        "list_events",
        details={
            "count": len(events),
            "period_hours": round((end_ms - start_ms) / 3_600_000, 1),
        },
    )

    return events


def _extract_event_metadata(ev: dict) -> dict:
    """Extract interesting metadata from an event."""
    meta = {}
    raw_meta = ev.get("metadata", {})

    # License plate
    plate = raw_meta.get("licensePlate")
    if plate and plate.get("name"):
        meta["license_plate"] = plate["name"]
        meta["license_plate_confidence"] = plate.get("confidenceLevel", 0)

    # Detected thumbnails with attributes
    thumbnails = raw_meta.get("detectedThumbnails", [])
    if thumbnails:
        detections = []
        for thumb in thumbnails:
            det = {
                "type": thumb.get("type", ""),
                "confidence": thumb.get("confidence", 0),
            }
            attrs = thumb.get("attributes", {})
            if attrs.get("vehicleType", {}).get("val"):
                det["vehicle_type"] = attrs["vehicleType"]["val"]
            if attrs.get("color", {}).get("val"):
                det["color"] = attrs["color"]["val"]
            detections.append(det)
        meta["detections"] = detections

    return meta


def get_event_thumbnail(event_id: str) -> str:
    """
    Get the thumbnail image for an event.

    Returns base64-encoded JPEG image.
    """
    event_id = validate_event_id(event_id)
    rate_limiter.check("thumbnail")

    resp = _session.get(
        f"/proxy/protect/api/events/{event_id}/thumbnail",
    )
    resp.raise_for_status()

    encoded = base64.b64encode(resp.content).decode("ascii")

    audit_log(
        "get_event_thumbnail",
        details={
            "event_id": event_id,
            "size_bytes": len(resp.content),
        },
    )

    return encoded


# ---------------------------------------------------------------------------
# Sensor Operations
# ---------------------------------------------------------------------------


def list_sensors() -> list[Sensor]:
    """List all sensor devices with current readings."""
    rate_limiter.check("read")

    bootstrap = _session.get_bootstrap()
    sensors = []

    for s in bootstrap.get("sensors", []):
        stats = s.get("stats", {})
        battery = s.get("batteryStatus", {})

        sensors.append(
            Sensor(
                id=s["id"],
                name=s.get("name", "Unknown"),
                model=s.get("marketName", s.get("type", "Unknown")),
                state=s.get("state", "UNKNOWN"),
                temperature=stats.get("temperature", {}).get("value"),
                humidity=stats.get("humidity", {}).get("value"),
                light_level=stats.get("light", {}).get("value"),
                is_motion_detected=s.get("isMotionDetected", False),
                is_opened=s.get("isOpened", False),
                battery_percent=battery.get("percentage"),
                alarm_triggered_at=_ts_to_iso(s.get("alarmTriggeredAt")),
            )
        )

    audit_log("list_sensors", details={"count": len(sensors)})
    return sensors


# ---------------------------------------------------------------------------
# Light Operations
# ---------------------------------------------------------------------------


def list_lights() -> list[Light]:
    """List all Protect-managed lights (Floodlights, etc.)."""
    rate_limiter.check("read")

    bootstrap = _session.get_bootstrap()
    lights = []

    for light_data in bootstrap.get("lights", []):
        settings = light_data.get("lightDeviceSettings", {})

        lights.append(
            Light(
                id=light_data["id"],
                name=light_data.get("name", "Unknown"),
                model=light_data.get("marketName", light_data.get("type", "Unknown")),
                state=light_data.get("state", "UNKNOWN"),
                is_on=light_data.get("isLightOn", False),
                is_dark=light_data.get("isDark", False),
                is_motion_detected=light_data.get("isPirMotionDetected", False),
                last_motion=_ts_to_iso(light_data.get("lastMotion")),
                led_level=settings.get("ledLevel", 0),
                pir_sensitivity=settings.get("pirSensitivity", 0),
            )
        )

    audit_log("list_lights", details={"count": len(lights)})
    return lights


def toggle_light(light_id: str, on: bool) -> Light:
    """
    Turn a Protect light on or off.

    Returns updated Light state.
    """
    light_id = validate_light_id(light_id)
    rate_limiter.check("write")

    # Use PATCH to update light on/off settings
    _session.patch(
        f"/proxy/protect/api/lights/{light_id}",
        json={"lightOnSettings": {"isLedForceOn": on}},
    )

    # Invalidate bootstrap cache to get fresh state
    _session.get_bootstrap(force_refresh=True)

    lights = list_lights()
    for light in lights:
        if light.id == light_id:
            audit_log(
                "toggle_light",
                details={
                    "light_id": light_id,
                    "light_name": light.name,
                    "action": "on" if on else "off",
                },
            )
            return light

    msg = f"Light not found after toggle: {light_id}"
    raise SecurityError(msg)


# ---------------------------------------------------------------------------
# Doorbell Operations
# ---------------------------------------------------------------------------


def list_doorbells() -> list[Doorbell]:
    """List all doorbell cameras with ring info."""
    rate_limiter.check("read")

    bootstrap = _session.get_bootstrap()
    doorbells = []

    for cam in bootstrap.get("cameras", []):
        feature_flags = cam.get("featureFlags", {})
        if not feature_flags.get("isDoorbell", False):
            continue

        lcd = cam.get("lcdMessage", {})
        lcd_text = lcd.get("text") if lcd else None

        doorbells.append(
            Doorbell(
                id=cam["id"],
                name=cam.get("name", "Unknown"),
                model=cam.get("marketName", cam.get("type", "Unknown")),
                state=cam.get("state", "UNKNOWN"),
                last_ring=_ts_to_iso(cam.get("lastRing")),
                lcd_message=lcd_text,
                has_package_camera=feature_flags.get("hasPackageCamera", False),
                smart_detect_types=cam.get("smartDetectSettings", {}).get("objectTypes", []),
            )
        )

    audit_log("list_doorbells", details={"count": len(doorbells)})
    return doorbells


# ---------------------------------------------------------------------------
# NVR / System Info
# ---------------------------------------------------------------------------


def get_nvr_info() -> NvrInfo:
    """Get NVR system status and health."""
    rate_limiter.check("read")

    bootstrap = _session.get_bootstrap()
    nvr = bootstrap.get("nvr", {})

    storage = nvr.get("storageStats", {})
    storage_used = storage.get("storageUsed", 0) or 0
    storage_total = storage.get("storageSize", 0) or 1  # avoid div by zero

    uptime = nvr.get("uptime", 0) or 0

    info = NvrInfo(
        name=nvr.get("name", "Unknown"),
        version=nvr.get("version", "Unknown"),
        firmware_version=nvr.get("firmwareVersion", "Unknown"),
        uptime_seconds=uptime,
        uptime_human=_format_uptime(uptime // 1000) if uptime > 1000 else _format_uptime(uptime),
        storage_used_bytes=storage_used,
        storage_total_bytes=storage_total,
        storage_used_percent=round((storage_used / storage_total) * 100, 1) if storage_total else 0,
        recording_retention_days=(nvr.get("recordingRetentionDurationMs", 0) or 0) // 86_400_000,
        camera_count=len(bootstrap.get("cameras", [])),
        sensor_count=len(bootstrap.get("sensors", [])),
        light_count=len(bootstrap.get("lights", [])),
        is_connected_to_cloud=nvr.get("isConnectedToCloud", False),
    )

    audit_log("get_nvr_info")
    return info


# ---------------------------------------------------------------------------
# Activity Summary
# ---------------------------------------------------------------------------


def get_recent_activity(hours: int = 24) -> ActivitySummary:
    """
    Get a summary of recent activity across all cameras and sensors.

    Args:
        hours: How many hours back to look (default 24, max 168).
    """
    hours = validate_hours(hours)

    now_ms = int(time.time() * 1000)
    start_ms = now_ms - (hours * 60 * 60 * 1000)

    events = list_events(start_ms=start_ms, end_ms=now_ms, max_results=100)

    # Aggregate
    motion_count = 0
    ring_count = 0
    sensor_count = 0
    smart_counts: dict[str, int] = {}
    camera_activity: dict[str, dict] = {}  # cam_id -> {name, count, last}

    for ev in events:
        if ev.type == "motion":
            motion_count += 1
        elif ev.type == "ring":
            ring_count += 1
        elif ev.type in ("sensorMotion", "sensorContact", "sensorAlarm"):
            sensor_count += 1

        for st in ev.smart_detect_types:
            smart_counts[st] = smart_counts.get(st, 0) + 1

        if ev.camera_id:
            if ev.camera_id not in camera_activity:
                camera_activity[ev.camera_id] = {
                    "name": ev.camera_name,
                    "event_count": 0,
                    "last_event": ev.start,
                }
            camera_activity[ev.camera_id]["event_count"] += 1

    cameras_with_activity = sorted(
        camera_activity.values(),
        key=lambda x: x["event_count"],
        reverse=True,
    )

    summary = ActivitySummary(
        period_hours=hours,
        total_events=len(events),
        motion_events=motion_count,
        smart_detections=smart_counts,
        ring_events=ring_count,
        cameras_with_activity=cameras_with_activity,
        sensor_events=sensor_count,
    )

    audit_log(
        "get_recent_activity",
        details={
            "hours": hours,
            "total_events": len(events),
        },
    )

    return summary


# ---------------------------------------------------------------------------
# System Status (combined overview)
# ---------------------------------------------------------------------------


def get_system_status() -> dict:
    """
    Get combined system status — NVR health + camera states + alerts.

    Designed for daily briefings and quick checks.
    """
    rate_limiter.check("read")

    nvr = get_nvr_info()
    cameras = list_cameras()
    sensors = list_sensors()
    lights = list_lights()

    # Check for issues
    issues = []
    disconnected = [c for c in cameras if c.state != "CONNECTED"]
    if disconnected:
        issues.append(
            f"{len(disconnected)} camera(s) disconnected: "
            + ", ".join(c.name for c in disconnected)
        )

    low_battery = [s for s in sensors if s.battery_percent is not None and s.battery_percent < 20]
    if low_battery:
        issues.append(
            f"{len(low_battery)} sensor(s) with low battery: "
            + ", ".join(f"{s.name} ({s.battery_percent}%)" for s in low_battery)
        )

    if nvr.storage_used_percent > 90:
        issues.append(f"NVR storage {nvr.storage_used_percent}% full")

    open_contacts = [s for s in sensors if s.is_opened]

    status = {
        "nvr": {
            "name": nvr.name,
            "version": nvr.version,
            "uptime": nvr.uptime_human,
            "storage_used_percent": nvr.storage_used_percent,
            "cloud_connected": nvr.is_connected_to_cloud,
        },
        "cameras": {
            "total": len(cameras),
            "connected": sum(1 for c in cameras if c.state == "CONNECTED"),
            "recording": sum(1 for c in cameras if c.is_recording),
            "motion_detected": [c.name for c in cameras if c.is_motion_detected],
        },
        "sensors": {
            "total": len(sensors),
            "open_contacts": [{"name": s.name, "is_opened": s.is_opened} for s in open_contacts],
            "readings": [
                {
                    "name": s.name,
                    "temperature": s.temperature,
                    "humidity": s.humidity,
                    "light": s.light_level,
                }
                for s in sensors
                if s.temperature is not None or s.humidity is not None
            ],
        },
        "lights": {
            "total": len(lights),
            "on": [light.name for light in lights if light.is_on],
        },
        "issues": issues,
        "all_ok": len(issues) == 0,
    }

    audit_log("get_system_status")
    return status
