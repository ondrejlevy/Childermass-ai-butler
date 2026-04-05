"""Mapy.com REST API client for Childermass Mapy MCP.

This module provides a Python wrapper around the Mapy.com REST API with
input validation, rate limiting, response caching, and audit logging.

API reference: https://api.mapy.com/v1/docs/
"""

import time
from dataclasses import dataclass, field
from typing import Any

import requests  # type: ignore[import-untyped]

from .auth import get_api_key
from .security import (
    SecurityError,
    audit_log,
    rate_limiter,
    sanitize_error_message,
    validate_coordinates,
    validate_departure,
    validate_geocode_type,
    validate_geometry_format,
    validate_language,
    validate_limit,
    validate_positions,
    validate_query,
    validate_route_type,
    validate_waypoints,
)


# Mapy.com API configuration
BASE_URL = "https://api.mapy.com/v1"
CACHE_TTL = 900  # 15 minutes in seconds


# ============================================================================
# Data Models
# ============================================================================


@dataclass
class RegionalEntity:
    """Single level in the regional structure."""

    name: str
    type: str
    iso_code: str | None = None


@dataclass
class GeocodedResult:
    """A single geocoded entity."""

    name: str
    label: str
    latitude: float
    longitude: float
    type: str
    location: str | None = None
    zip: str | None = None
    regional_structure: list[RegionalEntity] | None = None


@dataclass
class RoutePart:
    """Individual route segment between waypoints."""

    length: float  # meters
    duration: float  # seconds


@dataclass
class RoutePoint:
    """Start, end, or waypoint metadata."""

    original_lat: float
    original_lon: float
    mapped_lat: float
    mapped_lon: float
    snap_distance: float
    restricted: bool = False
    restriction_type: str | None = None


@dataclass
class Route:
    """Planned route result."""

    length: float  # meters
    duration: float  # seconds
    geometry: Any = None  # GeoJSON or polyline depending on format
    parts: list[RoutePart] = field(default_factory=list)
    route_points: list[RoutePoint] = field(default_factory=list)


@dataclass
class MatrixEntry:
    """Single matrix routing result between one start and one end."""

    length: float  # meters
    duration: float  # seconds


@dataclass
class MatrixResult:
    """Matrix routing response."""

    matrix: list[list[MatrixEntry]] = field(default_factory=list)


@dataclass
class ElevationResult:
    """Elevation data for a single point."""

    latitude: float
    longitude: float
    elevation: float  # meters


@dataclass
class TimezoneInfo:
    """Timezone information."""

    timezone_name: str
    current_time_abbreviation: str
    standard_time_abbreviation: str
    current_local_time: str
    current_utc_time: str
    current_utc_offset_seconds: int
    standard_utc_offset_seconds: int
    has_dst: bool
    is_dst_active: bool


# ============================================================================
# Response Cache
# ============================================================================


class ResponseCache:
    """Simple in-memory cache with TTL."""

    def __init__(self, ttl: int = CACHE_TTL):
        self.ttl = ttl
        self.cache: dict[str, tuple[Any, float]] = {}

    def get(self, key: str) -> Any | None:
        if key in self.cache:
            value, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                return value
            del self.cache[key]
        return None

    def set(self, key: str, value: Any) -> None:
        self.cache[key] = (value, time.time())

    def clear(self) -> None:
        self.cache.clear()


# ============================================================================
# Mapy Client
# ============================================================================


class MapyClient:
    """Mapy.com REST API client with caching and security."""

    def __init__(self, api_key: str | None = None, cache_ttl: int = CACHE_TTL):
        """Initialize Mapy.com client.

        Args:
            api_key: Mapy.com API key (if None, will load from auth).
            cache_ttl: Cache time-to-live in seconds.
        """
        if api_key is None:
            api_key = get_api_key()
        self.api_key = api_key
        self.cache = ResponseCache(ttl=cache_ttl)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Childermass-Mapy-MCP/1.0.0",
                "X-Mapy-Api-Key": self.api_key,
            }
        )

    def _make_request(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]:
        """Make API request with error handling.

        Args:
            endpoint: API endpoint path (appended to BASE_URL).
            params: Query parameters.

        Returns:
            JSON response (dict or list).

        Raises:
            SecurityError: On API errors or network issues.
        """
        url = f"{BASE_URL}{endpoint}"
        params = params or {}

        try:
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            json_data: dict[str, Any] | list[Any] = response.json()
            return json_data
        except requests.exceptions.HTTPError as e:
            if e.response is not None:
                status = e.response.status_code
                if status == 401:
                    msg = "API key is missing. Please check your Mapy.com API key."
                    raise SecurityError(msg)
                if status == 403:
                    msg = (
                        "Invalid API key or service not enabled. "
                        "Please verify your Mapy.com API key."
                    )
                    raise SecurityError(msg)
                if status == 404:
                    msg = "Resource not found."
                    raise SecurityError(msg)
                if status == 429:
                    msg = "API rate limit exceeded. Please try again later."
                    raise SecurityError(msg)
                try:
                    error_data = e.response.json()
                    message = error_data.get("message", str(e))
                except Exception:
                    message = str(e)
                msg = f"API error ({status}): {sanitize_error_message(Exception(message))}"
                raise SecurityError(msg)
            msg = f"HTTP error: {sanitize_error_message(e)}"
            raise SecurityError(msg) from e
        except requests.exceptions.RequestException as e:
            msg = f"Network error: {sanitize_error_message(e)}"
            raise SecurityError(msg) from e

    # ------------------------------------------------------------------ #
    # Geocoding
    # ------------------------------------------------------------------ #

    def geocode(
        self,
        query: str,
        lang: str = "cs",
        limit: int = 5,
        geocode_type: str | None = None,
        locality: str | None = None,
    ) -> list[GeocodedResult]:
        """Search for entities by textual query (forward geocoding).

        Args:
            query: Search expression (address, city, POI, …).
            lang: Preferred language.
            limit: Max results.
            geocode_type: Filter by entity type (e.g., "regional.address", "poi").
            locality: Restrict results to locality / country code.

        Returns:
            List of geocoded results.
        """
        query = validate_query(query)
        lang = validate_language(lang)
        limit = validate_limit(limit, max_limit=100)
        if geocode_type:
            geocode_type = validate_geocode_type(geocode_type)

        rate_limiter.check("geocode")

        cache_key = f"geocode:{query}:{lang}:{limit}:{geocode_type}:{locality}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            audit_log("geocode", details={"query": query, "cached": True})
            # Type guard for cached value
            if not isinstance(cached, list):
                msg = "Invalid cached geocode results"
                raise SecurityError(msg)
            return cached

        params: dict[str, Any] = {"query": query, "lang": lang, "limit": limit}
        if geocode_type:
            params["type"] = geocode_type
        if locality:
            params["locality"] = locality

        data = self._make_request("/geocode", params)
        results = self._parse_geocode_results(data)

        self.cache.set(cache_key, results)
        audit_log("geocode", details={"query": query, "count": len(results), "cached": False})
        return results

    def suggest(
        self,
        query: str,
        lang: str = "cs",
        limit: int = 5,
        geocode_type: str | None = None,
        locality: str | None = None,
        prefer_near_lat: float | None = None,
        prefer_near_lon: float | None = None,
    ) -> list[GeocodedResult]:
        """Suggest entities while typing (autocomplete geocoding).

        Args:
            query: Partial search expression.
            lang: Preferred language.
            limit: Max results.
            geocode_type: Filter by entity type.
            locality: Restrict by locality.
            prefer_near_lat: Prefer results near this latitude.
            prefer_near_lon: Prefer results near this longitude.

        Returns:
            List of geocoded results.
        """
        query = validate_query(query)
        lang = validate_language(lang)
        limit = validate_limit(limit, max_limit=100)
        if geocode_type:
            geocode_type = validate_geocode_type(geocode_type)
        if prefer_near_lat is not None and prefer_near_lon is not None:
            validate_coordinates(prefer_near_lat, prefer_near_lon)

        rate_limiter.check("suggest")

        params: dict[str, Any] = {"query": query, "lang": lang, "limit": limit}
        if geocode_type:
            params["type"] = geocode_type
        if locality:
            params["locality"] = locality
        if prefer_near_lat is not None and prefer_near_lon is not None:
            params["preferNear"] = f"{prefer_near_lon},{prefer_near_lat}"

        data = self._make_request("/suggest", params)
        results = self._parse_geocode_results(data)

        audit_log("suggest", details={"query": query, "count": len(results)})
        return results

    def reverse_geocode(
        self,
        lat: float,
        lon: float,
        lang: str = "cs",
    ) -> list[GeocodedResult]:
        """Get regional entities for coordinates (reverse geocoding).

        Args:
            lat: Latitude.
            lon: Longitude.
            lang: Preferred language.

        Returns:
            List of geocoded results.
        """
        lat, lon = validate_coordinates(lat, lon)
        lang = validate_language(lang)

        rate_limiter.check("rgeocode")

        cache_key = f"rgeocode:{lat},{lon}:{lang}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            audit_log("reverse_geocode", details={"lat": lat, "lon": lon, "cached": True})
            # Type guard for cached value
            if not isinstance(cached, list):
                msg = "Invalid cached reverse geocode results"
                raise SecurityError(msg)
            return cached

        params: dict[str, Any] = {"lon": lon, "lat": lat, "lang": lang}
        data = self._make_request("/rgeocode", params)
        results = self._parse_rgeocode_results(data)

        self.cache.set(cache_key, results)
        audit_log(
            "reverse_geocode",
            details={"lat": lat, "lon": lon, "count": len(results), "cached": False},
        )
        return results

    # ------------------------------------------------------------------ #
    # Routing
    # ------------------------------------------------------------------ #

    def plan_route(
        self,
        start_lat: float,
        start_lon: float,
        end_lat: float,
        end_lon: float,
        route_type: str = "car_fast",
        waypoints: list[tuple[float, float]] | None = None,
        avoid_toll: bool = False,
        avoid_highways: bool = False,
        departure: str | None = None,
        geometry_format: str = "geojson",
    ) -> Route:
        """Plan a route between two points.

        Args:
            start_lat: Start latitude.
            start_lon: Start longitude.
            end_lat: End latitude.
            end_lon: End longitude.
            route_type: Planning type (car_fast, foot_fast, etc.).
            waypoints: Optional via-points, max 15.
            avoid_toll: Avoid toll roads.
            avoid_highways: Avoid highways.
            departure: ISO-8601 departure time.
            geometry_format: Output geometry format.

        Returns:
            Route with length, duration, geometry.
        """
        start_lat, start_lon = validate_coordinates(start_lat, start_lon)
        end_lat, end_lon = validate_coordinates(end_lat, end_lon)
        route_type = validate_route_type(route_type)
        if waypoints:
            waypoints = validate_waypoints(waypoints)
        if departure:
            departure = validate_departure(departure)
        geometry_format = validate_geometry_format(geometry_format)

        rate_limiter.check("route")

        # Build params — Mapy.com uses "lon,lat" format
        params: dict[str, Any] = {
            "start": f"{start_lon},{start_lat}",
            "end": f"{end_lon},{end_lat}",
            "routeType": route_type,
            "format": geometry_format,
        }

        if waypoints:
            wp_strs = [f"{lon},{lat}" for lat, lon in waypoints]
            params["waypoints"] = "|".join(wp_strs)

        if avoid_toll:
            params["avoidToll"] = "true"
        if avoid_highways:
            params["avoidHighways"] = "true"
        if departure:
            params["departure"] = departure

        data = self._make_request("/routing/route", params)

        route = self._parse_route(data)

        audit_log(
            "plan_route",
            details={
                "start": f"{start_lat},{start_lon}",
                "end": f"{end_lat},{end_lon}",
                "route_type": route_type,
                "length_m": route.length,
                "duration_s": route.duration,
            },
        )

        return route

    def matrix_routing(
        self,
        starts: list[tuple[float, float]],
        ends: list[tuple[float, float]] | None = None,
        route_type: str = "car_fast",
        avoid_toll: bool = False,
    ) -> MatrixResult:
        """Calculate times and distances between M origins and N destinations.

        The product of starts × ends must not exceed 100.

        Args:
            starts: List of (lat, lon) start coordinates.
            ends: List of (lat, lon) end coordinates (if None, routes between starts).
            route_type: Planning type.
            avoid_toll: Avoid toll roads.

        Returns:
            MatrixResult with 2D array of length/duration.
        """
        if not isinstance(starts, (list, tuple)) or len(starts) < 1:
            msg = "At least one start is required"
            raise SecurityError(msg)

        for i, s in enumerate(starts):
            if not isinstance(s, (list, tuple)) or len(s) != 2:
                msg = f"Start {i} must be a [lat, lon] pair"
                raise SecurityError(msg)
            validate_coordinates(s[0], s[1])

        if ends is not None:
            for i, e in enumerate(ends):
                if not isinstance(e, (list, tuple)) or len(e) != 2:
                    msg = f"End {i} must be a [lat, lon] pair"
                    raise SecurityError(msg)
                validate_coordinates(e[0], e[1])

            count = len(starts) * len(ends)
        else:
            count = len(starts) * len(starts)

        if count > 100:
            msg = f"starts × ends = {count} exceeds maximum of 100"
            raise SecurityError(msg)

        route_type = validate_route_type(route_type)
        rate_limiter.check("matrix")

        # Build params
        starts_str = "|".join(f"{lon},{lat}" for lat, lon in starts)
        params: dict[str, Any] = {
            "starts": starts_str,
            "routeType": route_type,
        }

        if ends is not None:
            ends_str = "|".join(f"{lon},{lat}" for lat, lon in ends)
            params["ends"] = ends_str

        if avoid_toll:
            params["avoidToll"] = "true"

        data = self._make_request("/routing/matrix-m", params)

        result = self._parse_matrix(data)

        audit_log(
            "matrix_routing",
            details={
                "starts": len(starts),
                "ends": len(ends) if ends else len(starts),
                "route_type": route_type,
            },
        )

        return result

    # ------------------------------------------------------------------ #
    # Elevation
    # ------------------------------------------------------------------ #

    def get_elevation(
        self,
        positions: list[tuple[float, float]],
    ) -> list[ElevationResult]:
        """Get elevation for one or more positions.

        Args:
            positions: List of (lat, lon) tuples (max 256).

        Returns:
            List of ElevationResult.
        """
        positions = validate_positions(positions)
        rate_limiter.check("elevation")

        cache_key = f"elevation:{positions}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            audit_log("get_elevation", details={"count": len(positions), "cached": True})
            # Type guard for cached value
            if not isinstance(cached, list):
                msg = "Invalid cached elevation results"
                raise SecurityError(msg)
            return cached

        positions_str = "|".join(f"{lon},{lat}" for lat, lon in positions)
        params: dict[str, Any] = {"positions": positions_str}

        data = self._make_request("/elevation", params)

        results = []
        items = data if isinstance(data, list) else data.get("items", data.get("elevations", []))
        for item in items:
            pos = item.get("position", {})
            results.append(
                ElevationResult(
                    latitude=pos.get("lat", 0.0),
                    longitude=pos.get("lon", 0.0),
                    elevation=item.get("elevation", 0.0),
                )
            )

        self.cache.set(cache_key, results)
        audit_log("get_elevation", details={"count": len(results), "cached": False})
        return results

    # ------------------------------------------------------------------ #
    # Timezone
    # ------------------------------------------------------------------ #

    def get_timezone_by_coords(
        self,
        lat: float,
        lon: float,
    ) -> TimezoneInfo:
        """Get timezone info for coordinates.

        Args:
            lat: Latitude.
            lon: Longitude.

        Returns:
            TimezoneInfo.
        """
        lat, lon = validate_coordinates(lat, lon)
        rate_limiter.check("timezone")

        cache_key = f"tz:{lat},{lon}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            audit_log("get_timezone_by_coords", details={"lat": lat, "lon": lon, "cached": True})
            # Type guard for cached value
            if not isinstance(cached, TimezoneInfo):
                msg = "Invalid cached timezone info"
                raise SecurityError(msg)
            return cached

        params: dict[str, Any] = {"lon": lon, "lat": lat}
        data = self._make_request("/timezone/coordinate", params)

        result = self._parse_timezone(data)
        self.cache.set(cache_key, result)
        audit_log("get_timezone_by_coords", details={"lat": lat, "lon": lon, "cached": False})
        return result

    def get_timezone_by_name(self, iana_name: str) -> TimezoneInfo:
        """Get timezone info by IANA name.

        Args:
            iana_name: IANA timezone name (e.g., "Europe/Prague").

        Returns:
            TimezoneInfo.
        """
        if not iana_name or not isinstance(iana_name, str):
            msg = "Timezone name must be a non-empty string"
            raise SecurityError(msg)
        iana_name = iana_name.strip()
        if len(iana_name) > 100:
            msg = "Timezone name too long"
            raise SecurityError(msg)

        rate_limiter.check("timezone")

        cache_key = f"tz_name:{iana_name}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            audit_log("get_timezone_by_name", details={"name": iana_name, "cached": True})
            # Type guard for cached value
            if not isinstance(cached, TimezoneInfo):
                msg = "Invalid cached timezone info"
                raise SecurityError(msg)
            return cached

        params: dict[str, Any] = {"name": iana_name}
        data = self._make_request("/timezone/timezone", params)

        result = self._parse_timezone(data)
        self.cache.set(cache_key, result)
        audit_log("get_timezone_by_name", details={"name": iana_name, "cached": False})
        return result

    # ------------------------------------------------------------------ #
    # Response Parsers
    # ------------------------------------------------------------------ #

    def _parse_geocode_results(self, data: dict | list) -> list[GeocodedResult]:
        """Parse geocode / suggest response into GeocodedResult list."""
        items = data if isinstance(data, list) else data.get("items", [])
        results: list[GeocodedResult] = []
        for item in items:
            pos = item.get("position", {})
            reg = item.get("regionalStructure", [])
            regional = (
                [
                    RegionalEntity(
                        name=r.get("name", ""),
                        type=r.get("type", ""),
                        iso_code=r.get("isoCode"),
                    )
                    for r in reg
                ]
                if reg
                else None
            )

            results.append(
                GeocodedResult(
                    name=item.get("name", ""),
                    label=item.get("label", ""),
                    latitude=pos.get("lat", 0.0),
                    longitude=pos.get("lon", 0.0),
                    type=item.get("type", ""),
                    location=item.get("location"),
                    zip=item.get("zip"),
                    regional_structure=regional,
                )
            )
        return results

    def _parse_rgeocode_results(self, data: dict | list) -> list[GeocodedResult]:
        """Parse reverse geocode response into GeocodedResult list."""
        items = data if isinstance(data, list) else data.get("items", [])
        results: list[GeocodedResult] = []
        for item in items:
            pos = item.get("position", {})
            results.append(
                GeocodedResult(
                    name=item.get("name", ""),
                    label=item.get("label", item.get("type", "")),
                    latitude=pos.get("lat", 0.0),
                    longitude=pos.get("lon", 0.0),
                    type=item.get("type", ""),
                    location=item.get("location"),
                    zip=item.get("zip"),
                    regional_structure=None,
                )
            )
        return results

    def _parse_route(self, data: dict | list) -> Route:
        """Parse plan route response into Route."""
        # API may return a list of routes — take the first one
        if isinstance(data, list):
            if len(data) == 0:
                return Route(length=0.0, duration=0.0, geometry=None, parts=[], route_points=[])
            data = data[0]

        assert isinstance(data, dict)
        parts_data = data.get("parts", [])
        parts = [
            RoutePart(
                length=p.get("length", 0.0),
                duration=p.get("duration", 0.0),
            )
            for p in parts_data
        ]

        rp_data = data.get("routePoints", [])
        route_points = []
        for rp in rp_data:
            orig = rp.get("originalPosition", [0.0, 0.0])
            mapped = rp.get("mappedPosition", [0.0, 0.0])
            # API returns positions as [longitude, latitude] arrays
            if isinstance(orig, list):
                orig_lon = orig[0] if len(orig) > 0 else 0.0
                orig_lat = orig[1] if len(orig) > 1 else 0.0
            else:
                orig_lat = orig.get("lat", 0.0)
                orig_lon = orig.get("lon", 0.0)
            if isinstance(mapped, list):
                mapped_lon = mapped[0] if len(mapped) > 0 else 0.0
                mapped_lat = mapped[1] if len(mapped) > 1 else 0.0
            else:
                mapped_lat = mapped.get("lat", 0.0)
                mapped_lon = mapped.get("lon", 0.0)
            route_points.append(
                RoutePoint(
                    original_lat=orig_lat,
                    original_lon=orig_lon,
                    mapped_lat=mapped_lat,
                    mapped_lon=mapped_lon,
                    snap_distance=rp.get("snapDistance", 0.0),
                    restricted=rp.get("restricted", False),
                    restriction_type=rp.get("restrictionType"),
                )
            )

        return Route(
            length=data.get("length", 0.0),
            duration=data.get("duration", 0.0),
            geometry=data.get("geometry"),
            parts=parts,
            route_points=route_points,
        )

    def _parse_matrix(self, data: dict | list) -> MatrixResult:
        """Parse matrix routing response into MatrixResult."""
        raw_matrix = data if isinstance(data, list) else data.get("matrix", [])
        matrix: list[list[MatrixEntry]] = []
        for row in raw_matrix:
            matrix_row: list[MatrixEntry] = []
            for cell in row:
                matrix_row.append(
                    MatrixEntry(
                        length=cell.get("length", 0.0),
                        duration=cell.get("duration", 0.0),
                    )
                )
            matrix.append(matrix_row)
        return MatrixResult(matrix=matrix)

    def _parse_timezone(self, data: dict | list) -> TimezoneInfo:
        """Parse timezone response into TimezoneInfo."""
        if isinstance(data, list):
            data = data[0] if data else {}
        return TimezoneInfo(
            timezone_name=data.get("timezoneName", ""),
            current_time_abbreviation=data.get("currentTimeAbbreviation", ""),
            standard_time_abbreviation=data.get("standardTimeAbbreviation", ""),
            current_local_time=data.get("currentLocalTime", ""),
            current_utc_time=data.get("currentUtcTime", ""),
            current_utc_offset_seconds=data.get("currentUtcOffsetSeconds", 0),
            standard_utc_offset_seconds=data.get("standardUtcOffsetSeconds", 0),
            has_dst=data.get("hasDst", False),
            is_dst_active=data.get("isDstActive", False),
        )

    def clear_cache(self) -> None:
        """Clear all cached data."""
        self.cache.clear()


# Global client instance (lazy initialization)
_client: MapyClient | None = None


def get_client() -> MapyClient:
    """Get or create global MapyClient instance.

    Returns:
        MapyClient: Global client instance.
    """
    global _client
    if _client is None:
        _client = MapyClient()
    return _client
