"""Childermass Mapy.com MCP Server – FastMCP tools for Mapy.com REST API.

This module provides MCP tools for geocoding, route planning, elevation
lookup, and timezone queries via the Mapy.com REST API.
"""

from dataclasses import asdict

from mcp.server.fastmcp import FastMCP

from .client import get_client
from .security import SecurityError, sanitize_error_message


# Initialize FastMCP server
mcp = FastMCP("childermass-mapy")


# ============================================================================
# Geocoding Tools
# ============================================================================


@mcp.tool()
def mapy_search_places(
    query: str,
    lang: str = "cs",
    limit: int = 5,
    geocode_type: str | None = None,
    locality: str | None = None,
) -> dict:
    """Search for places, addresses, or POIs by text query using Mapy.com geocoding.

    Args:
        query: Search expression (address, city, POI name, etc.)
            Examples: "Václavské náměstí 1, Praha", "Lidl Brno", "letiště Praha"
        lang: Language for results – "cs" (Czech), "en", "de", "sk", "pl", etc.
        limit: Maximum number of results (1-100, default: 5)
        geocode_type: Filter by entity type – "regional", "regional.address",
            "regional.municipality", "regional.street", "poi", "coordinate"
        locality: Restrict to a locality (e.g., "Praha", "cz", "sk")

    Returns:
        dict: List of matching places with name, label, coordinates, type,
        location, zip code, and regional structure.

    Examples:
        mapy_search_places("Národní muzeum", "cs", 3)
        mapy_search_places("Lidl", "cs", 5, "poi", "Brno")
        mapy_search_places("Hlavní 123", "cs", 1, "regional.address")
    """
    try:
        client = get_client()
        results = client.geocode(
            query=query,
            lang=lang,
            limit=limit,
            geocode_type=geocode_type,
            locality=locality,
        )
        return {
            "results": [asdict(r) for r in results],
            "count": len(results),
            "query": query,
        }
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def mapy_suggest_places(
    query: str,
    lang: str = "cs",
    limit: int = 5,
    geocode_type: str | None = None,
    locality: str | None = None,
    prefer_near: str | None = None,
) -> dict:
    """Suggest places while typing (autocomplete) – handles incomplete queries and typos.

    Args:
        query: Partial search expression (handles typos and incomplete input)
        lang: Language for results
        limit: Maximum number of results (1-100, default: 5)
        geocode_type: Filter by entity type
        locality: Restrict to a locality
        prefer_near: Prefer results near coordinates as "lat,lon"

    Returns:
        dict: List of suggested places with name, coordinates, type.

    Examples:
        mapy_suggest_places("vaclavs", "cs", 5)
        mapy_suggest_places("rest", "cs", 5, "poi", "Praha")
        mapy_suggest_places("lékár", "cs", 3, None, None, "50.0755,14.4378")
    """
    try:
        client = get_client()

        prefer_near_lat = None
        prefer_near_lon = None
        if prefer_near:
            parts = prefer_near.split(",")
            if len(parts) == 2:
                prefer_near_lat = float(parts[0].strip())
                prefer_near_lon = float(parts[1].strip())

        results = client.suggest(
            query=query,
            lang=lang,
            limit=limit,
            geocode_type=geocode_type,
            locality=locality,
            prefer_near_lat=prefer_near_lat,
            prefer_near_lon=prefer_near_lon,
        )
        return {
            "results": [asdict(r) for r in results],
            "count": len(results),
            "query": query,
        }
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def mapy_reverse_geocode(
    lat: float,
    lon: float,
    lang: str = "cs",
) -> dict:
    """Get address and location info for given coordinates (reverse geocoding).

    Args:
        lat: Latitude (-90 to 90)
        lon: Longitude (-180 to 180)
        lang: Language for results

    Returns:
        dict: Regional entities at that position (address, city, country, etc.)

    Examples:
        mapy_reverse_geocode(50.0755, 14.4378, "cs")  # Prague center
        mapy_reverse_geocode(49.1951, 16.6068, "en")  # Brno center
    """
    try:
        client = get_client()
        results = client.reverse_geocode(lat=lat, lon=lon, lang=lang)
        return {
            "results": [asdict(r) for r in results],
            "count": len(results),
            "coordinates": {"lat": lat, "lon": lon},
        }
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ============================================================================
# Routing Tools
# ============================================================================


@mcp.tool()
def mapy_plan_route(
    start: str,
    end: str,
    route_type: str = "car_fast",
    waypoints: str | None = None,
    avoid_toll: bool = False,
    avoid_highways: bool = False,
    departure: str | None = None,
) -> dict:
    """Plan a route between two points with optional waypoints.

    Args:
        start: Start coordinates as "lat,lon" (e.g., "50.0755,14.4378")
        end: End coordinates as "lat,lon"
        route_type: Planning type – "car_fast" (default), "car_fast_traffic",
            "car_short", "foot_fast", "foot_hiking", "bike_road", "bike_mountain"
        waypoints: Optional via-points as "lat1,lon1|lat2,lon2|..." (max 15)
        avoid_toll: Avoid toll roads (default: false)
        avoid_highways: Avoid highways (default: false)
        departure: Departure time in ISO-8601 format (e.g., "2026-02-14T08:00:00")
            Affects time-based closures and restrictions.

    Returns:
        dict: Route with length (meters), duration (seconds), geometry,
        route segments, and waypoint details.

    Examples:
        mapy_plan_route("50.0755,14.4378", "49.1951,16.6068")  # Praha → Brno
        mapy_plan_route("50.0755,14.4378", "49.1951,16.6068", "car_fast_traffic")
        mapy_plan_route("50.0755,14.4378", "48.2082,16.3738", "car_fast",
                        "49.1951,16.6068", False, False, "2026-03-01T08:00:00")
    """
    try:
        client = get_client()

        start_lat, start_lon = _parse_coords(start)
        end_lat, end_lon = _parse_coords(end)

        wp_list = None
        if waypoints:
            wp_list = []
            for wp_str in waypoints.split("|"):
                wlat, wlon = _parse_coords(wp_str.strip())
                wp_list.append((wlat, wlon))

        route = client.plan_route(
            start_lat=start_lat,
            start_lon=start_lon,
            end_lat=end_lat,
            end_lon=end_lon,
            route_type=route_type,
            waypoints=wp_list,
            avoid_toll=avoid_toll,
            avoid_highways=avoid_highways,
            departure=departure,
        )

        result = asdict(route)
        # Add human-readable duration
        result["duration_minutes"] = round(route.duration / 60, 1)
        result["length_km"] = round(route.length / 1000, 2)

        return result
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def mapy_travel_time(
    start: str,
    end: str,
    route_type: str = "car_fast",
) -> dict:
    """Get travel time and distance between two points (simplified routing).

    Args:
        start: Start coordinates as "lat,lon"
        end: End coordinates as "lat,lon"
        route_type: Planning type – "car_fast", "car_fast_traffic",
            "car_short", "foot_fast", "foot_hiking", "bike_road", "bike_mountain"

    Returns:
        dict: Travel time in minutes and distance in km.

    Examples:
        mapy_travel_time("50.0755,14.4378", "49.1951,16.6068")  # Praha → Brno
        mapy_travel_time("50.0755,14.4378", "49.1951,16.6068", "foot_fast")
    """
    try:
        client = get_client()

        start_lat, start_lon = _parse_coords(start)
        end_lat, end_lon = _parse_coords(end)

        route = client.plan_route(
            start_lat=start_lat,
            start_lon=start_lon,
            end_lat=end_lat,
            end_lon=end_lon,
            route_type=route_type,
            geometry_format="polyline",  # Lightweight — we only need time/distance
        )

        return {
            "duration_seconds": route.duration,
            "duration_minutes": round(route.duration / 60, 1),
            "length_meters": route.length,
            "length_km": round(route.length / 1000, 2),
            "route_type": route_type,
            "start": start,
            "end": end,
        }
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def mapy_compare_routes(
    start: str,
    end: str,
    route_types: str = "car_fast,foot_fast,bike_road",
) -> dict:
    """Compare travel time and distance across multiple transport modes.

    Args:
        start: Start coordinates as "lat,lon"
        end: End coordinates as "lat,lon"
        route_types: Comma-separated route types to compare
            (e.g., "car_fast,foot_fast,bike_road")

    Returns:
        dict: Comparison of routes with time and distance per mode.

    Examples:
        mapy_compare_routes("50.0755,14.4378", "50.0880,14.4208")
        mapy_compare_routes("50.0755,14.4378", "49.1951,16.6068",
                            "car_fast,car_fast_traffic,car_short")
    """
    try:
        client = get_client()

        start_lat, start_lon = _parse_coords(start)
        end_lat, end_lon = _parse_coords(end)

        types = [t.strip() for t in route_types.split(",") if t.strip()]
        if len(types) < 1:
            return {"error": "At least one route type is required"}
        if len(types) > 7:
            return {"error": "Maximum 7 route types for comparison"}

        comparison = []
        for rt in types:
            try:
                route = client.plan_route(
                    start_lat=start_lat,
                    start_lon=start_lon,
                    end_lat=end_lat,
                    end_lon=end_lon,
                    route_type=rt,
                    geometry_format="polyline",
                )
                comparison.append({
                    "route_type": rt,
                    "duration_seconds": route.duration,
                    "duration_minutes": round(route.duration / 60, 1),
                    "length_meters": route.length,
                    "length_km": round(route.length / 1000, 2),
                })
            except Exception as e:
                comparison.append({
                    "route_type": rt,
                    "error": sanitize_error_message(e),
                })

        # Sort by duration (fastest first), errors last
        comparison.sort(
            key=lambda x: float(str(x.get("duration_seconds", float("inf"))))
        )

        fastest = next(
            (c for c in comparison if "duration_seconds" in c), None
        )

        return {
            "start": start,
            "end": end,
            "comparison": comparison,
            "fastest": fastest["route_type"] if fastest else None,
        }
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def mapy_find_nearest(
    origin: str,
    destinations: str,
    route_type: str = "car_fast",
) -> dict:
    """Find the nearest destination from a list using matrix routing.

    Useful for finding the closest pharmacy, post office, gas station, etc.

    Args:
        origin: Origin coordinates as "lat,lon"
        destinations: Pipe-separated destination coordinates "lat1,lon1|lat2,lon2|..."
            (max 100 destinations)
        route_type: Planning type (default: "car_fast")

    Returns:
        dict: Destinations ranked by travel time with the nearest first.

    Examples:
        mapy_find_nearest(
            "50.0755,14.4378",
            "50.0880,14.4208|50.0600,14.4100|50.1000,14.4500"
        )
    """
    try:
        client = get_client()

        origin_lat, origin_lon = _parse_coords(origin)

        dest_list = []
        for d_str in destinations.split("|"):
            d_str = d_str.strip()
            if d_str:
                dlat, dlon = _parse_coords(d_str)
                dest_list.append((dlat, dlon))

        if len(dest_list) < 1:
            return {"error": "At least one destination is required"}
        if len(dest_list) > 100:
            return {"error": "Maximum 100 destinations allowed"}

        matrix = client.matrix_routing(
            starts=[(origin_lat, origin_lon)],
            ends=dest_list,
            route_type=route_type,
        )

        # Parse results — matrix is 1×N
        results = []
        if matrix.matrix and len(matrix.matrix) > 0:
            for i, entry in enumerate(matrix.matrix[0]):
                results.append({
                    "destination_index": i,
                    "destination": f"{dest_list[i][0]},{dest_list[i][1]}",
                    "duration_seconds": entry.duration,
                    "duration_minutes": round(entry.duration / 60, 1),
                    "length_meters": entry.length,
                    "length_km": round(entry.length / 1000, 2),
                })

        # Sort by duration
        results.sort(key=lambda x: float(str(x.get("duration_seconds", float("inf")))))

        return {
            "origin": origin,
            "nearest": results[0] if results else None,
            "destinations_ranked": results,
            "route_type": route_type,
        }
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ============================================================================
# Elevation Tool
# ============================================================================


@mcp.tool()
def mapy_get_elevation(
    positions: str,
) -> dict:
    """Get elevation (meters above sea level) for one or more positions.

    Args:
        positions: Pipe-separated coordinates "lat1,lon1|lat2,lon2|..." (max 256)

    Returns:
        dict: Elevation in meters for each position.

    Examples:
        mapy_get_elevation("50.0755,14.4378")  # Prague
        mapy_get_elevation("50.0755,14.4378|49.1951,16.6068")  # Prague & Brno
    """
    try:
        client = get_client()

        pos_list = []
        for p_str in positions.split("|"):
            p_str = p_str.strip()
            if p_str:
                plat, plon = _parse_coords(p_str)
                pos_list.append((plat, plon))

        results = client.get_elevation(pos_list)
        return {
            "elevations": [asdict(r) for r in results],
            "count": len(results),
        }
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ============================================================================
# Timezone Tool
# ============================================================================


@mcp.tool()
def mapy_get_timezone(
    location: str,
) -> dict:
    """Get timezone, local time, and UTC offset for coordinates or IANA timezone name.

    Args:
        location: Either coordinates as "lat,lon" (e.g., "50.0755,14.4378")
            or an IANA timezone name (e.g., "Europe/Prague")

    Returns:
        dict: Timezone name, current local time, UTC offset, DST status.

    Examples:
        mapy_get_timezone("50.0755,14.4378")  # Prague by coordinates
        mapy_get_timezone("Europe/Prague")      # Prague by IANA name
        mapy_get_timezone("40.7128,-74.0060")   # New York by coordinates
    """
    try:
        client = get_client()

        # Try to parse as coordinates
        if "," in location:
            parts = location.split(",")
            if len(parts) == 2:
                try:
                    lat = float(parts[0].strip())
                    lon = float(parts[1].strip())
                    if -90 <= lat <= 90 and -180 <= lon <= 180:
                        result = client.get_timezone_by_coords(lat, lon)
                        return asdict(result)
                except ValueError:
                    pass  # Not coordinates, try as IANA name

        # Treat as IANA name
        result = client.get_timezone_by_name(location)
        return asdict(result)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ============================================================================
# Helper Functions
# ============================================================================


def _parse_coords(coord_str: str) -> tuple[float, float]:
    """Parse "lat,lon" string into (lat, lon) tuple.

    Args:
        coord_str: Coordinates as "lat,lon"

    Returns:
        Tuple of (latitude, longitude).

    Raises:
        SecurityError: If format is invalid.
    """
    if not coord_str or not isinstance(coord_str, str):
        raise SecurityError("Coordinates must be a non-empty string in 'lat,lon' format")

    parts = coord_str.strip().split(",")
    if len(parts) != 2:
        raise SecurityError(
            f"Invalid coordinate format: '{coord_str}' (expected 'lat,lon')"
        )

    try:
        lat = float(parts[0].strip())
        lon = float(parts[1].strip())
    except ValueError:
        raise SecurityError(
            f"Invalid coordinate values in: '{coord_str}' (expected numbers)"
        )

    from .security import validate_coordinates
    validate_coordinates(lat, lon)

    return lat, lon


if __name__ == "__main__":
    # Run MCP server
    mcp.run()
