"""
Childermass Places MCP Server

Custom Places API (New) MCP server for Claude Code / OpenCode.
All data stays local – we only call official Google APIs.

Security: All tool responses go through error sanitization so that
OAuth tokens, API keys, credentials, or internal paths are never
leaked to the LLM.

Run with: python -m childermass.places_mcp.server
"""

from mcp.server.fastmcp import FastMCP

from . import client
from .client import _place_to_dict
from .security import SecurityError, sanitize_error_message


# Create FastMCP server
mcp = FastMCP("childermass-places")


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
# Search tools
# ---------------------------------------------------------------------------


@mcp.tool()
def places_text_search(
    query: str,
    included_type: str = "",
    max_results: int = 10,
    language_code: str = "",
    region_code: str = "",
    location_bias_lat: float | None = None,
    location_bias_lng: float | None = None,
    location_bias_radius: float | None = None,
    open_now: bool = False,
    min_rating: float | None = None,
    rank_preference: str = "",
) -> list[dict] | dict:
    """
    Search for places using a text query.

    Args:
        query: Search text (e.g. "pizza restaurants in Prague",
               "hardware store near me", "dentist open now").
        included_type: Filter by place type (e.g. "restaurant",
                       "gas_station", "pharmacy").
        max_results: Number of results to return (1-20, default 10).
        language_code: BCP-47 language code for results (e.g. "cs", "en").
        region_code: CLDR region code (e.g. "CZ", "US").
        location_bias_lat: Latitude to bias results toward.
        location_bias_lng: Longitude to bias results toward.
        location_bias_radius: Radius in meters for location bias.
        open_now: If true, only return places that are open now.
        min_rating: Minimum Google rating (0.0-5.0).
        rank_preference: "RELEVANCE" or "DISTANCE".

    Returns:
        List of places with name, address, rating, type, etc.
    """
    try:
        places = client.text_search(
            query,
            included_type=included_type or None,
            max_results=max_results,
            language_code=language_code or None,
            region_code=region_code or None,
            location_bias_lat=location_bias_lat,
            location_bias_lng=location_bias_lng,
            location_bias_radius=location_bias_radius,
            open_now=open_now if open_now else None,
            min_rating=min_rating,
            rank_preference=rank_preference or None,
        )
        return [_place_to_dict(p) for p in places]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def places_nearby_search(
    latitude: float,
    longitude: float,
    radius: float,
    included_types: str = "",
    excluded_types: str = "",
    max_results: int = 10,
    language_code: str = "",
    region_code: str = "",
    rank_preference: str = "",
) -> list[dict] | dict:
    """
    Search for places near a geographic location.

    Args:
        latitude: Center point latitude (-90 to 90).
        longitude: Center point longitude (-180 to 180).
        radius: Search radius in meters (max 50000).
        included_types: Comma-separated place types to include
                        (e.g. "restaurant,cafe").
        excluded_types: Comma-separated place types to exclude.
        max_results: Number of results (1-20, default 10).
        language_code: BCP-47 language code.
        region_code: CLDR region code.
        rank_preference: "POPULARITY" or "DISTANCE".

    Returns:
        List of nearby places with name, address, distance, etc.
    """
    try:
        inc_types = (
            [t.strip() for t in included_types.split(",") if t.strip()] if included_types else None
        )
        exc_types = (
            [t.strip() for t in excluded_types.split(",") if t.strip()] if excluded_types else None
        )

        places = client.nearby_search(
            latitude,
            longitude,
            radius,
            included_types=inc_types,
            excluded_types=exc_types,
            max_results=max_results,
            language_code=language_code or None,
            region_code=region_code or None,
            rank_preference=rank_preference or None,
        )
        return [_place_to_dict(p) for p in places]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def places_search_with_filters(
    query: str,
    price_levels: str = "",
    min_rating: float | None = None,
    open_now: bool = False,
    included_type: str = "",
    max_results: int = 10,
    language_code: str = "",
    region_code: str = "",
    location_bias_lat: float | None = None,
    location_bias_lng: float | None = None,
    location_bias_radius: float | None = None,
) -> list[dict] | dict:
    """
    Search for places with advanced filters.

    Convenient for filtering by price, rating, and open status.

    Args:
        query: Search text (e.g. "Italian restaurant").
        price_levels: Comma-separated price levels:
                      "PRICE_LEVEL_FREE", "PRICE_LEVEL_INEXPENSIVE",
                      "PRICE_LEVEL_MODERATE", "PRICE_LEVEL_EXPENSIVE",
                      "PRICE_LEVEL_VERY_EXPENSIVE".
        min_rating: Minimum Google rating (0.0-5.0).
        open_now: If true, only return currently open places.
        included_type: Filter by place type.
        max_results: Number of results (1-20).
        language_code: BCP-47 language code.
        region_code: CLDR region code.
        location_bias_lat: Latitude to bias results toward.
        location_bias_lng: Longitude to bias results toward.
        location_bias_radius: Radius for location bias in meters.

    Returns:
        Filtered list of places.
    """
    try:
        price_list = (
            [p.strip() for p in price_levels.split(",") if p.strip()] if price_levels else None
        )

        places = client.search_with_filters(
            query,
            price_levels=price_list,
            min_rating=min_rating,
            open_now=open_now,
            included_type=included_type or None,
            max_results=max_results,
            language_code=language_code or None,
            region_code=region_code or None,
            location_bias_lat=location_bias_lat,
            location_bias_lng=location_bias_lng,
            location_bias_radius=location_bias_radius,
        )
        return [_place_to_dict(p) for p in places]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Detail tools
# ---------------------------------------------------------------------------


@mcp.tool()
def places_get_details(
    place_id: str,
    language_code: str = "",
    region_code: str = "",
) -> dict:
    """
    Get detailed information about a specific place.

    Args:
        place_id: Google Place ID (e.g. "ChIJN1t_tDeuEmsRUsoyG83frY4").
        language_code: BCP-47 language code (e.g. "cs", "en").
        region_code: CLDR region code (e.g. "CZ").

    Returns:
        Detailed place info including address, phone, website,
        hours, reviews, photos, attributes, and accessibility.
    """
    try:
        place = client.get_place_details(
            place_id,
            language_code=language_code or None,
            region_code=region_code or None,
        )
        return _place_to_dict(place)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def places_get_opening_hours(
    place_id: str,
    language_code: str = "",
) -> dict:
    """
    Get opening hours for a place.

    Args:
        place_id: Google Place ID.
        language_code: BCP-47 language code.

    Returns:
        Opening hours including whether the place is open now
        and weekly schedule.
    """
    try:
        mask = "id,displayName,regularOpeningHours,currentOpeningHours,businessStatus"
        place = client.get_place_details(
            place_id,
            language_code=language_code or None,
            field_mask=mask,
        )

        result: dict = {
            "id": place.id,
            "display_name": place.display_name,
            "business_status": place.business_status,
        }

        if place.opening_hours:
            result["opening_hours"] = {
                "open_now": place.opening_hours.open_now,
                "weekday_text": place.opening_hours.weekday_text,
            }
        else:
            result["opening_hours"] = None

        return result
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def places_get_reviews(
    place_id: str,
    language_code: str = "",
) -> dict:
    """
    Get user reviews for a place.

    Args:
        place_id: Google Place ID.
        language_code: BCP-47 language code.

    Returns:
        Place reviews with author, rating, text, and date.
    """
    try:
        mask = "id,displayName,reviews,rating,userRatingCount"
        place = client.get_place_details(
            place_id,
            language_code=language_code or None,
            field_mask=mask,
        )

        return {
            "id": place.id,
            "display_name": place.display_name,
            "rating": place.rating,
            "user_rating_count": place.user_rating_count,
            "reviews": [
                {
                    "author": r.author,
                    "rating": r.rating,
                    "text": r.text,
                    "relative_time": r.relative_publish_time,
                }
                for r in place.reviews
            ],
        }
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Autocomplete tool
# ---------------------------------------------------------------------------


@mcp.tool()
def places_autocomplete(
    input_text: str,
    location_bias_lat: float | None = None,
    location_bias_lng: float | None = None,
    location_bias_radius: float | None = None,
    included_primary_types: str = "",
    language_code: str = "",
    region_code: str = "",
    include_query_predictions: bool = False,
) -> list[dict] | dict:
    """
    Get autocomplete suggestions for partial place input.

    Useful for interactive search as user types.

    Args:
        input_text: Partial text to autocomplete (e.g. "Starbu").
        location_bias_lat: Latitude to bias suggestions toward.
        location_bias_lng: Longitude to bias suggestions toward.
        location_bias_radius: Radius in meters for bias.
        included_primary_types: Comma-separated types to filter
                                (e.g. "restaurant,cafe").
        language_code: BCP-47 language code.
        region_code: CLDR region code.
        include_query_predictions: Include query-type predictions.

    Returns:
        List of autocomplete suggestions with place IDs and text.
    """
    try:
        types_list = (
            [t.strip() for t in included_primary_types.split(",") if t.strip()]
            if included_primary_types
            else None
        )

        suggestions = client.autocomplete(
            input_text,
            location_bias_lat=location_bias_lat,
            location_bias_lng=location_bias_lng,
            location_bias_radius=location_bias_radius,
            included_primary_types=types_list,
            language_code=language_code or None,
            region_code=region_code or None,
            include_query_predictions=include_query_predictions,
        )

        return [
            {
                "type": s.type,
                "text": s.text,
                "place_id": s.place_id,
                "main_text": s.structured_main_text,
                "secondary_text": s.structured_secondary_text,
                "types": s.types,
                "distance_meters": s.distance_meters,
            }
            for s in suggestions
        ]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Photo tool
# ---------------------------------------------------------------------------


@mcp.tool()
def places_get_photo(
    photo_resource_name: str,
    max_width: int = 400,
    max_height: int = 400,
) -> dict:
    """
    Get a photo URI for a place photo.

    Use the photo resource names from places_get_details results.

    Args:
        photo_resource_name: Photo resource name from place details
                             (e.g. "places/ChIJ.../photos/...").
        max_width: Max photo width in pixels (1-4800, default 400).
        max_height: Max photo height in pixels (1-4800, default 400).

    Returns:
        Photo URI that can be used to display or download the image.
    """
    try:
        uri = client.get_place_photo_uri(
            photo_resource_name,
            max_width=max_width,
            max_height=max_height,
        )
        return {"photo_uri": uri, "resource_name": photo_resource_name}
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Smart home / personal assistant convenience tools
# ---------------------------------------------------------------------------


@mcp.tool()
def places_find_nearby_service(
    service_type: str,
    latitude: float,
    longitude: float,
    radius: float = 5000.0,
    max_results: int = 10,
    language_code: str = "",
) -> list[dict] | dict:
    """
    Find service providers near a location (smart home assistant).

    Great for finding plumbers, electricians, locksmiths, mechanics,
    doctors, vets, and other local services.

    Args:
        service_type: Type of service needed (e.g. "plumber",
                      "electrician", "locksmith", "veterinarian").
        latitude: Home/target latitude.
        longitude: Home/target longitude.
        radius: Search radius in meters (default 5000).
        max_results: Number of results (1-20).
        language_code: BCP-47 language code.

    Returns:
        List of service providers with contact info and ratings.
    """
    try:
        places = client.find_nearby_services(
            service_type,
            latitude,
            longitude,
            radius,
            max_results=max_results,
            language_code=language_code or None,
        )
        return [_place_to_dict(p) for p in places]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def places_find_restaurants(
    latitude: float,
    longitude: float,
    radius: float = 2000.0,
    cuisine: str = "",
    min_rating: float | None = None,
    price_levels: str = "",
    open_now: bool = False,
    max_results: int = 10,
    language_code: str = "",
) -> list[dict] | dict:
    """
    Find restaurants near a location with filters.

    Args:
        latitude: Center latitude.
        longitude: Center longitude.
        radius: Search radius in meters (default 2000).
        cuisine: Cuisine type (e.g. "italian", "thai", "sushi").
        min_rating: Minimum Google rating (0.0-5.0).
        price_levels: Comma-separated price levels:
                      "PRICE_LEVEL_INEXPENSIVE",
                      "PRICE_LEVEL_MODERATE",
                      "PRICE_LEVEL_EXPENSIVE".
        open_now: Only show open restaurants.
        max_results: Number of results (1-20).
        language_code: BCP-47 language code.

    Returns:
        List of restaurants with ratings, price, hours, etc.
    """
    try:
        query_parts = []
        if cuisine:
            query_parts.append(cuisine)
        query_parts.append("restaurant")
        query = " ".join(query_parts)

        price_list = (
            [p.strip() for p in price_levels.split(",") if p.strip()] if price_levels else None
        )

        places = client.search_with_filters(
            query,
            price_levels=price_list,
            min_rating=min_rating,
            open_now=open_now,
            included_type="restaurant",
            max_results=max_results,
            language_code=language_code or None,
            location_bias_lat=latitude,
            location_bias_lng=longitude,
            location_bias_radius=radius,
        )
        return [_place_to_dict(p) for p in places]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def places_find_ev_chargers(
    latitude: float,
    longitude: float,
    radius: float = 5000.0,
    connector_types: str = "",
    min_charging_rate_kw: float | None = None,
    max_results: int = 10,
    language_code: str = "",
) -> list[dict] | dict:
    """
    Find EV charging stations near a location.

    Args:
        latitude: Center latitude.
        longitude: Center longitude.
        radius: Search radius in meters (default 5000).
        connector_types: Comma-separated EV connector types
                         (e.g. "EV_CONNECTOR_TYPE_CCS_COMBO_2,
                         EV_CONNECTOR_TYPE_TYPE2").
        min_charging_rate_kw: Min charging rate in kilowatts.
        max_results: Number of results (1-20).
        language_code: BCP-47 language code.

    Returns:
        List of EV charging stations with connector info.
    """
    try:
        conn_types = (
            [c.strip() for c in connector_types.split(",") if c.strip()]
            if connector_types
            else None
        )

        places = client.find_ev_chargers(
            latitude,
            longitude,
            radius,
            connector_types=conn_types,
            min_charging_rate_kw=min_charging_rate_kw,
            max_results=max_results,
            language_code=language_code or None,
        )
        return [_place_to_dict(p) for p in places]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    mcp.run()
