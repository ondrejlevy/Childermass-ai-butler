"""
Google Places API (New) Client Wrapper

Provides a clean interface for Places API (New) v1 operations with
integrated security.  All data stays local – we only call official
Google APIs via REST.

The Places API (New) uses direct REST calls (not the discovery-based
google-api-python-client) because API v1 endpoints follow a different
pattern than legacy Workspace APIs.

Security features:
- Input validation on all public functions
- Rate limiting per account / operation
- Audit logging for all operations
- Error message sanitization to prevent credential leaks
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from google.auth.transport.requests import AuthorizedSession

from .auth import get_authenticated_credentials, list_authenticated_accounts
from .security import (
    DETAIL_FIELD_MASK_DETAILED,
    FIELD_MASK_BASIC,
    FIELD_MASK_STANDARD,
    SecurityError,
    audit_log,
    rate_limiter,
    sanitize_error_message,
    validate_autocomplete_input,
    validate_ev_connector_types,
    validate_language_code,
    validate_latitude,
    validate_longitude,
    validate_max_results,
    validate_min_rating,
    validate_photo_max_dimension,
    validate_photo_resource_name,
    validate_place_id,
    validate_place_types,
    validate_price_levels,
    validate_query,
    validate_radius,
    validate_rank_preference,
    validate_region_code,
)


logger = logging.getLogger(__name__)

# Base URL for Places API (New) v1
PLACES_API_BASE = "https://places.googleapis.com/v1"

# Module-level session cache – keyed by account
_sessions: dict[str, AuthorizedSession] = {}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class LatLng:
    """Geographic coordinates."""

    latitude: float
    longitude: float


@dataclass
class PlacePhoto:
    """Photo reference for a place."""

    name: str  # resource name: places/{id}/photos/{id}
    width_px: int = 0
    height_px: int = 0
    author_attributions: list[dict[str, str]] = field(default_factory=list)


@dataclass
class PlaceReview:
    """A user review for a place."""

    author: str
    rating: float
    text: str
    relative_publish_time: str = ""
    publish_time: str = ""
    language_code: str = ""


@dataclass
class OpeningHoursPeriod:
    """A single opening hours period."""

    open_day: str = ""
    open_hour: int = 0
    open_minute: int = 0
    close_day: str = ""
    close_hour: int = 0
    close_minute: int = 0


@dataclass
class OpeningHours:
    """Opening hours for a place."""

    open_now: bool | None = None
    weekday_text: list[str] = field(default_factory=list)
    periods: list[OpeningHoursPeriod] = field(default_factory=list)


@dataclass
class Place:
    """
    Main place data structure.

    Maps to the Google Places API (New) Place resource.
    """

    id: str
    display_name: str = ""
    formatted_address: str = ""
    short_address: str = ""
    location: LatLng | None = None
    types: list[str] = field(default_factory=list)
    primary_type: str = ""
    primary_type_display_name: str = ""
    business_status: str = ""
    rating: float | None = None
    user_rating_count: int = 0
    price_level: str = ""
    website_uri: str = ""
    phone_number: str = ""
    google_maps_uri: str = ""
    opening_hours: OpeningHours | None = None
    editorial_summary: str = ""
    reviews: list[PlaceReview] = field(default_factory=list)
    photos: list[PlacePhoto] = field(default_factory=list)
    # Attributes
    delivery: bool | None = None
    dine_in: bool | None = None
    takeout: bool | None = None
    reservable: bool | None = None
    serves_breakfast: bool | None = None
    serves_lunch: bool | None = None
    serves_dinner: bool | None = None
    serves_beer: bool | None = None
    serves_wine: bool | None = None
    serves_cocktails: bool | None = None
    serves_vegetarian_food: bool | None = None
    outdoor_seating: bool | None = None
    good_for_children: bool | None = None
    good_for_groups: bool | None = None
    allows_dogs: bool | None = None
    restroom: bool | None = None
    # Accessibility
    wheelchair_accessible_parking: bool | None = None
    wheelchair_accessible_entrance: bool | None = None
    wheelchair_accessible_restroom: bool | None = None
    wheelchair_accessible_seating: bool | None = None
    # Parking
    parking_options: dict[str, bool] = field(default_factory=dict)
    # Payment
    payment_options: dict[str, bool] = field(default_factory=dict)
    # EV
    ev_charge_options: dict[str, Any] = field(default_factory=dict)
    # AI summaries
    generative_summary: str = ""
    review_summary: str = ""
    neighborhood_summary: str = ""


@dataclass
class AutocompleteSuggestion:
    """An autocomplete suggestion (place or query prediction)."""

    type: str  # "place" or "query"
    text: str = ""
    place_id: str = ""
    place_name: str = ""
    structured_main_text: str = ""
    structured_secondary_text: str = ""
    types: list[str] = field(default_factory=list)
    distance_meters: int | None = None


# ---------------------------------------------------------------------------
# Session / service helpers
# ---------------------------------------------------------------------------


def _get_session(account: str | None = None) -> AuthorizedSession:
    """
    Get an authenticated HTTP session for the Places API.

    Uses google.auth.transport.requests.AuthorizedSession which
    automatically handles token refresh.
    """
    global _sessions

    if account is None:
        accounts = list_authenticated_accounts()
        if not accounts:
            msg = (
                "No authenticated Places API accounts found. Run:\n"
                "  python -m childermass.places_mcp.auth --account=your@email.com"
            )
            raise RuntimeError(msg)
        account = accounts[0]

    if account in _sessions:
        return _sessions[account]

    creds = get_authenticated_credentials(account)
    session = AuthorizedSession(creds)
    _sessions[account] = session
    return session


def _api_get(
    path: str,
    field_mask: str,
    params: dict[str, str] | None = None,
    account: str | None = None,
) -> dict:
    """Make an authenticated GET request to the Places API."""
    session = _get_session(account)
    url = f"{PLACES_API_BASE}/{path}"

    headers = {
        "X-Goog-FieldMask": field_mask,
    }

    resp = session.get(url, headers=headers, params=params or {})

    if resp.status_code != 200:
        error_body = resp.text[:500]
        msg = f"Places API error ({resp.status_code}): {error_body}"
        raise RuntimeError(msg)

    return resp.json()


def _api_post(
    path: str,
    body: dict,
    field_mask: str,
    account: str | None = None,
) -> dict:
    """Make an authenticated POST request to the Places API."""
    session = _get_session(account)
    url = f"{PLACES_API_BASE}/{path}"

    headers = {
        "Content-Type": "application/json",
        "X-Goog-FieldMask": field_mask,
    }

    resp = session.post(url, json=body, headers=headers)

    if resp.status_code != 200:
        error_body = resp.text[:500]
        msg = f"Places API error ({resp.status_code}): {error_body}"
        raise RuntimeError(msg)

    return resp.json()


# ---------------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------------


def _parse_place(data: dict) -> Place:
    """Parse a Place API response dict into a Place dataclass."""
    location = None
    loc_data = data.get("location")
    if loc_data:
        location = LatLng(
            latitude=loc_data.get("latitude", 0.0),
            longitude=loc_data.get("longitude", 0.0),
        )

    # Parse opening hours
    opening_hours = None
    oh_data = data.get("regularOpeningHours") or data.get("currentOpeningHours")
    if oh_data:
        periods = []
        for p in oh_data.get("periods", []):
            open_info = p.get("open", {})
            close_info = p.get("close", {})
            periods.append(
                OpeningHoursPeriod(
                    open_day=str(open_info.get("day", "")),
                    open_hour=open_info.get("hour", 0),
                    open_minute=open_info.get("minute", 0),
                    close_day=str(close_info.get("day", "")),
                    close_hour=close_info.get("hour", 0),
                    close_minute=close_info.get("minute", 0),
                )
            )
        opening_hours = OpeningHours(
            open_now=oh_data.get("openNow"),
            weekday_text=oh_data.get("weekdayDescriptions", []),
            periods=periods,
        )

    # Parse photos
    photos = []
    for photo_data in data.get("photos", []):
        photos.append(
            PlacePhoto(
                name=photo_data.get("name", ""),
                width_px=photo_data.get("widthPx", 0),
                height_px=photo_data.get("heightPx", 0),
                author_attributions=[
                    {
                        "displayName": a.get("displayName", ""),
                        "uri": a.get("uri", ""),
                    }
                    for a in photo_data.get("authorAttributions", [])
                ],
            )
        )

    # Parse reviews
    reviews = []
    for rev_data in data.get("reviews", []):
        author_attr = rev_data.get("authorAttribution", {})
        original_text = rev_data.get("originalText") or rev_data.get("text", {})
        reviews.append(
            PlaceReview(
                author=author_attr.get("displayName", ""),
                rating=rev_data.get("rating", 0.0),
                text=(
                    original_text.get("text", "")
                    if isinstance(original_text, dict)
                    else str(original_text)
                ),
                relative_publish_time=rev_data.get("relativePublishTimeDescription", ""),
                publish_time=rev_data.get("publishTime", ""),
                language_code=(
                    original_text.get("languageCode", "") if isinstance(original_text, dict) else ""
                ),
            )
        )

    # Parse display name
    display_name_data = data.get("displayName", {})
    display_name = (
        display_name_data.get("text", "")
        if isinstance(display_name_data, dict)
        else str(display_name_data)
    )

    # Parse primary type display name
    ptdn = data.get("primaryTypeDisplayName", {})
    primary_type_display = ptdn.get("text", "") if isinstance(ptdn, dict) else str(ptdn)

    # Parse editorial / AI summaries
    editorial = data.get("editorialSummary", {})
    editorial_text = editorial.get("text", "") if isinstance(editorial, dict) else ""
    generative = data.get("generativeSummary", {})
    generative_text = ""
    if isinstance(generative, dict):
        overview = generative.get("overview", {})
        generative_text = overview.get("text", "") if isinstance(overview, dict) else ""
    review_summary = data.get("reviewSummary", {})
    review_summary_text = review_summary.get("text", "") if isinstance(review_summary, dict) else ""
    neighborhood = data.get("neighborhoodSummary", {})
    neighborhood_text = neighborhood.get("text", "") if isinstance(neighborhood, dict) else ""

    # Accessibility
    accessibility = data.get("accessibilityOptions", {})

    return Place(
        id=data.get("id", ""),
        display_name=display_name,
        formatted_address=data.get("formattedAddress", ""),
        short_address=data.get("shortFormattedAddress", ""),
        location=location,
        types=data.get("types", []),
        primary_type=data.get("primaryType", ""),
        primary_type_display_name=primary_type_display,
        business_status=data.get("businessStatus", ""),
        rating=data.get("rating"),
        user_rating_count=data.get("userRatingCount", 0),
        price_level=data.get("priceLevel", ""),
        website_uri=data.get("websiteUri", ""),
        phone_number=data.get("internationalPhoneNumber", "")
        or data.get("nationalPhoneNumber", ""),
        google_maps_uri=data.get("googleMapsUri", ""),
        opening_hours=opening_hours,
        editorial_summary=editorial_text,
        reviews=reviews,
        photos=photos,
        delivery=data.get("delivery"),
        dine_in=data.get("dineIn"),
        takeout=data.get("takeout"),
        reservable=data.get("reservable"),
        serves_breakfast=data.get("servesBreakfast"),
        serves_lunch=data.get("servesLunch"),
        serves_dinner=data.get("servesDinner"),
        serves_beer=data.get("servesBeer"),
        serves_wine=data.get("servesWine"),
        serves_cocktails=data.get("servesCocktails"),
        serves_vegetarian_food=data.get("servesVegetarianFood"),
        outdoor_seating=data.get("outdoorSeating"),
        good_for_children=data.get("goodForChildren"),
        good_for_groups=data.get("goodForGroups"),
        allows_dogs=data.get("allowsDogs"),
        restroom=data.get("restroom"),
        wheelchair_accessible_parking=accessibility.get("wheelchairAccessibleParking"),
        wheelchair_accessible_entrance=accessibility.get("wheelchairAccessibleEntrance"),
        wheelchair_accessible_restroom=accessibility.get("wheelchairAccessibleRestroom"),
        wheelchair_accessible_seating=accessibility.get("wheelchairAccessibleSeating"),
        parking_options=data.get("parkingOptions", {}),
        payment_options=data.get("paymentOptions", {}),
        ev_charge_options=data.get("evChargeOptions", {}),
        generative_summary=generative_text,
        review_summary=review_summary_text,
        neighborhood_summary=neighborhood_text,
    )


def _parse_autocomplete_suggestion(data: dict) -> AutocompleteSuggestion:
    """Parse autocomplete suggestion from API response."""
    place_pred = data.get("placePrediction")
    query_pred = data.get("queryPrediction")

    if place_pred:
        text_data = place_pred.get("text", {})
        structured = place_pred.get("structuredFormat", {})
        main_text = structured.get("mainText", {})
        secondary_text = structured.get("secondaryText", {})

        return AutocompleteSuggestion(
            type="place",
            text=text_data.get("text", ""),
            place_id=place_pred.get("placeId", ""),
            place_name=place_pred.get("place", ""),
            structured_main_text=main_text.get("text", ""),
            structured_secondary_text=secondary_text.get("text", ""),
            types=place_pred.get("types", []),
            distance_meters=place_pred.get("distanceMeters"),
        )
    if query_pred:
        text_data = query_pred.get("text", {})
        return AutocompleteSuggestion(
            type="query",
            text=text_data.get("text", ""),
        )

    return AutocompleteSuggestion(type="unknown")


def _place_to_dict(place: Place) -> dict:
    """Convert a Place dataclass to a clean dict for MCP responses."""
    result: dict[str, Any] = {
        "id": place.id,
        "display_name": place.display_name,
    }

    if place.formatted_address:
        result["formatted_address"] = place.formatted_address
    if place.short_address:
        result["short_address"] = place.short_address
    if place.location:
        result["location"] = {
            "latitude": place.location.latitude,
            "longitude": place.location.longitude,
        }
    if place.types:
        result["types"] = place.types
    if place.primary_type:
        result["primary_type"] = place.primary_type
    if place.primary_type_display_name:
        result["primary_type_display_name"] = place.primary_type_display_name
    if place.business_status:
        result["business_status"] = place.business_status
    if place.rating is not None:
        result["rating"] = place.rating
    if place.user_rating_count:
        result["user_rating_count"] = place.user_rating_count
    if place.price_level:
        result["price_level"] = place.price_level
    if place.website_uri:
        result["website_uri"] = place.website_uri
    if place.phone_number:
        result["phone_number"] = place.phone_number
    if place.google_maps_uri:
        result["google_maps_uri"] = place.google_maps_uri
    if place.editorial_summary:
        result["editorial_summary"] = place.editorial_summary
    if place.generative_summary:
        result["generative_summary"] = place.generative_summary
    if place.review_summary:
        result["review_summary"] = place.review_summary
    if place.neighborhood_summary:
        result["neighborhood_summary"] = place.neighborhood_summary

    # Opening hours
    if place.opening_hours:
        oh: dict[str, Any] = {}
        if place.opening_hours.open_now is not None:
            oh["open_now"] = place.opening_hours.open_now
        if place.opening_hours.weekday_text:
            oh["weekday_text"] = place.opening_hours.weekday_text
        if oh:
            result["opening_hours"] = oh

    # Reviews
    if place.reviews:
        result["reviews"] = [
            {
                "author": r.author,
                "rating": r.rating,
                "text": r.text,
                "relative_time": r.relative_publish_time,
            }
            for r in place.reviews
        ]

    # Photos (just names for separate retrieval)
    if place.photos:
        result["photos"] = [
            {"name": p.name, "width": p.width_px, "height": p.height_px} for p in place.photos
        ]

    # Boolean attributes – only include non-None
    attrs: dict[str, bool] = {}
    for attr_name in [
        "delivery",
        "dine_in",
        "takeout",
        "reservable",
        "serves_breakfast",
        "serves_lunch",
        "serves_dinner",
        "serves_beer",
        "serves_wine",
        "serves_cocktails",
        "serves_vegetarian_food",
        "outdoor_seating",
        "good_for_children",
        "good_for_groups",
        "allows_dogs",
        "restroom",
    ]:
        val = getattr(place, attr_name, None)
        if val is not None:
            attrs[attr_name] = val
    if attrs:
        result["attributes"] = attrs

    # Accessibility
    access: dict[str, bool] = {}
    for attr_name in [
        "wheelchair_accessible_parking",
        "wheelchair_accessible_entrance",
        "wheelchair_accessible_restroom",
        "wheelchair_accessible_seating",
    ]:
        val = getattr(place, attr_name, None)
        if val is not None:
            access[attr_name] = val
    if access:
        result["accessibility"] = access

    # Parking / payment / EV
    if place.parking_options:
        result["parking_options"] = place.parking_options
    if place.payment_options:
        result["payment_options"] = place.payment_options
    if place.ev_charge_options:
        result["ev_charge_options"] = place.ev_charge_options

    return result


# ---------------------------------------------------------------------------
# Public API: Text Search
# ---------------------------------------------------------------------------


def text_search(
    query: str,
    *,
    included_type: str | None = None,
    max_results: int = 10,
    language_code: str | None = None,
    region_code: str | None = None,
    location_bias_lat: float | None = None,
    location_bias_lng: float | None = None,
    location_bias_radius: float | None = None,
    open_now: bool | None = None,
    min_rating: float | None = None,
    price_levels: list[str] | None = None,
    rank_preference: str | None = None,
    field_mask: str | None = None,
    account: str | None = None,
) -> list[Place]:
    """
    Search for places using a text query.

    Args:
        query: Search string (e.g. "pizza restaurants in Prague")
        included_type: Filter by place type (e.g. "restaurant")
        max_results: Number of results (1-20, default 10)
        language_code: BCP-47 language code (e.g. "cs", "en")
        region_code: CLDR region code (e.g. "cz", "us")
        location_bias_lat: Latitude to bias results toward
        location_bias_lng: Longitude to bias results toward
        location_bias_radius: Radius in meters for location bias
        open_now: If True, only return currently open places
        min_rating: Minimum rating filter (0.0-5.0)
        price_levels: Filter by price levels
        rank_preference: "RELEVANCE" or "DISTANCE"
        field_mask: Custom field mask (defaults to STANDARD)
        account: Account to use for authentication

    Returns:
        List of Place objects matching the search.
    """
    # Validate inputs
    query = validate_query(query)
    max_results = validate_max_results(max_results)

    if included_type:
        included_type = validate_place_types([included_type])[0]
    if language_code:
        language_code = validate_language_code(language_code)
    if region_code:
        region_code = validate_region_code(region_code)
    if min_rating is not None:
        min_rating = validate_min_rating(min_rating)
    if price_levels:
        price_levels = validate_price_levels(price_levels)
    if rank_preference:
        rank_preference = validate_rank_preference(rank_preference)

    # Rate limiting
    acct_key = account or "default"
    rate_limiter.check(acct_key, "text_search")

    # Build request body
    body: dict[str, Any] = {
        "textQuery": query,
        "pageSize": max_results,
    }

    if included_type:
        body["includedType"] = included_type
    if language_code:
        body["languageCode"] = language_code
    if region_code:
        body["regionCode"] = region_code
    if open_now is not None:
        body["openNow"] = open_now
    if min_rating is not None:
        body["minRating"] = min_rating
    if price_levels:
        body["priceLevels"] = price_levels
    if rank_preference:
        body["rankPreference"] = rank_preference

    # Location bias
    if location_bias_lat is not None and location_bias_lng is not None:
        lat = validate_latitude(location_bias_lat)
        lng = validate_longitude(location_bias_lng)
        circle: dict[str, Any] = {
            "center": {"latitude": lat, "longitude": lng},
        }
        if location_bias_radius is not None:
            circle["radius"] = validate_radius(location_bias_radius)
        body["locationBias"] = {"circle": circle}

    mask = field_mask or FIELD_MASK_STANDARD

    try:
        data = _api_post("places:searchText", body, mask, account)

        places = []
        for place_data in data.get("places", []):
            places.append(_parse_place(place_data))

        audit_log(
            "text_search",
            acct_key,
            {
                "query": query,
                "results": len(places),
            },
        )

        return places

    except SecurityError:
        raise
    except Exception as e:
        audit_log(
            "text_search",
            acct_key,
            {
                "query": query,
                "error": sanitize_error_message(e),
            },
            success=False,
        )
        raise RuntimeError(sanitize_error_message(e)) from None


# ---------------------------------------------------------------------------
# Public API: Nearby Search
# ---------------------------------------------------------------------------


def nearby_search(
    latitude: float,
    longitude: float,
    radius: float,
    *,
    included_types: list[str] | None = None,
    excluded_types: list[str] | None = None,
    max_results: int = 10,
    language_code: str | None = None,
    region_code: str | None = None,
    rank_preference: str | None = None,
    field_mask: str | None = None,
    account: str | None = None,
) -> list[Place]:
    """
    Search for places near a geographic location.

    Args:
        latitude: Center latitude (-90 to 90)
        longitude: Center longitude (-180 to 180)
        radius: Search radius in meters (0-50000)
        included_types: Place types to include
        excluded_types: Place types to exclude
        max_results: Number of results (1-20, default 10)
        language_code: BCP-47 language code
        region_code: CLDR region code
        rank_preference: "POPULARITY" or "DISTANCE"
        field_mask: Custom field mask
        account: Account for authentication

    Returns:
        List of Place objects near the specified location.
    """
    latitude = validate_latitude(latitude)
    longitude = validate_longitude(longitude)
    radius = validate_radius(radius)
    max_results = validate_max_results(max_results)

    if included_types:
        included_types = validate_place_types(included_types)
    if excluded_types:
        excluded_types = validate_place_types(excluded_types)
    if language_code:
        language_code = validate_language_code(language_code)
    if region_code:
        region_code = validate_region_code(region_code)
    if rank_preference:
        rank_preference = validate_rank_preference(rank_preference)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "nearby_search")

    body: dict[str, Any] = {
        "locationRestriction": {
            "circle": {
                "center": {"latitude": latitude, "longitude": longitude},
                "radius": radius,
            }
        },
        "maxResultCount": max_results,
    }

    if included_types:
        body["includedTypes"] = included_types
    if excluded_types:
        body["excludedTypes"] = excluded_types
    if language_code:
        body["languageCode"] = language_code
    if region_code:
        body["regionCode"] = region_code
    if rank_preference:
        body["rankPreference"] = rank_preference

    mask = field_mask or FIELD_MASK_STANDARD

    try:
        data = _api_post("places:searchNearby", body, mask, account)

        places = []
        for place_data in data.get("places", []):
            places.append(_parse_place(place_data))

        audit_log(
            "nearby_search",
            acct_key,
            {
                "location": f"{latitude},{longitude}",
                "radius": radius,
                "results": len(places),
            },
        )

        return places

    except SecurityError:
        raise
    except Exception as e:
        audit_log(
            "nearby_search",
            acct_key,
            {
                "error": sanitize_error_message(e),
            },
            success=False,
        )
        raise RuntimeError(sanitize_error_message(e)) from None


# ---------------------------------------------------------------------------
# Public API: Place Details
# ---------------------------------------------------------------------------


def get_place_details(
    place_id: str,
    *,
    language_code: str | None = None,
    region_code: str | None = None,
    field_mask: str | None = None,
    account: str | None = None,
) -> Place:
    """
    Get detailed information about a specific place.

    Args:
        place_id: Google Place ID (e.g. "ChIJ...")
        language_code: BCP-47 language code
        region_code: CLDR region code
        field_mask: Custom field mask (defaults to DETAILED)
        account: Account for authentication

    Returns:
        Place object with detailed information.
    """
    place_id = validate_place_id(place_id)

    if language_code:
        language_code = validate_language_code(language_code)
    if region_code:
        region_code = validate_region_code(region_code)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "place_details")

    mask = field_mask or DETAIL_FIELD_MASK_DETAILED

    params: dict[str, str] = {}
    if language_code:
        params["languageCode"] = language_code
    if region_code:
        params["regionCode"] = region_code

    try:
        data = _api_get(f"places/{place_id}", mask, params, account)

        place = _parse_place(data)

        audit_log("place_details", acct_key, {"place_id": place_id})

        return place

    except SecurityError:
        raise
    except Exception as e:
        audit_log(
            "place_details",
            acct_key,
            {
                "place_id": place_id,
                "error": sanitize_error_message(e),
            },
            success=False,
        )
        raise RuntimeError(sanitize_error_message(e)) from None


# ---------------------------------------------------------------------------
# Public API: Autocomplete
# ---------------------------------------------------------------------------


def autocomplete(
    input_text: str,
    *,
    location_bias_lat: float | None = None,
    location_bias_lng: float | None = None,
    location_bias_radius: float | None = None,
    included_primary_types: list[str] | None = None,
    included_region_codes: list[str] | None = None,
    language_code: str | None = None,
    region_code: str | None = None,
    include_query_predictions: bool = False,
    origin_lat: float | None = None,
    origin_lng: float | None = None,
    account: str | None = None,
) -> list[AutocompleteSuggestion]:
    """
    Get autocomplete suggestions for a partial text input.

    Args:
        input_text: Partial text to autocomplete
        location_bias_lat: Latitude to bias results
        location_bias_lng: Longitude to bias results
        location_bias_radius: Radius in meters for bias
        included_primary_types: Filter by primary types
        included_region_codes: Filter by region codes
        language_code: BCP-47 language code
        region_code: CLDR region code
        include_query_predictions: Include query predictions
        origin_lat: Origin latitude for distance calculation
        origin_lng: Origin longitude for distance calculation
        account: Account for authentication

    Returns:
        List of autocomplete suggestions.
    """
    input_text = validate_autocomplete_input(input_text)

    if included_primary_types:
        included_primary_types = validate_place_types(included_primary_types)
    if language_code:
        language_code = validate_language_code(language_code)
    if region_code:
        region_code = validate_region_code(region_code)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "autocomplete")

    body: dict[str, Any] = {
        "input": input_text,
    }

    if language_code:
        body["languageCode"] = language_code
    if region_code:
        body["regionCode"] = region_code
    if include_query_predictions:
        body["includeQueryPredictions"] = True
    if included_primary_types:
        body["includedPrimaryTypes"] = included_primary_types
    if included_region_codes:
        validated_regions = [validate_region_code(rc) for rc in included_region_codes]
        body["includedRegionCodes"] = validated_regions

    # Location bias
    if location_bias_lat is not None and location_bias_lng is not None:
        lat = validate_latitude(location_bias_lat)
        lng = validate_longitude(location_bias_lng)
        circle: dict[str, Any] = {
            "center": {"latitude": lat, "longitude": lng},
        }
        if location_bias_radius is not None:
            circle["radius"] = validate_radius(location_bias_radius)
        body["locationBias"] = {"circle": circle}

    # Origin for distance
    if origin_lat is not None and origin_lng is not None:
        body["origin"] = {
            "latitude": validate_latitude(origin_lat),
            "longitude": validate_longitude(origin_lng),
        }

    try:
        # Autocomplete doesn't use standard field masks the same way
        session = _get_session(account)
        url = f"{PLACES_API_BASE}/places:autocomplete"
        headers = {"Content-Type": "application/json"}
        resp = session.post(url, json=body, headers=headers)

        if resp.status_code != 200:
            error_body = resp.text[:500]
            msg = f"Places API error ({resp.status_code}): {error_body}"
            raise RuntimeError(msg)

        data = resp.json()
        suggestions = []
        for suggestion in data.get("suggestions", []):
            suggestions.append(_parse_autocomplete_suggestion(suggestion))

        audit_log(
            "autocomplete",
            acct_key,
            {
                "input": input_text,
                "results": len(suggestions),
            },
        )

        return suggestions

    except SecurityError:
        raise
    except Exception as e:
        audit_log(
            "autocomplete",
            acct_key,
            {
                "input": input_text,
                "error": sanitize_error_message(e),
            },
            success=False,
        )
        raise RuntimeError(sanitize_error_message(e)) from None


# ---------------------------------------------------------------------------
# Public API: Place Photos
# ---------------------------------------------------------------------------


def get_place_photo_uri(
    photo_resource_name: str,
    *,
    max_width: int = 400,
    max_height: int = 400,
    account: str | None = None,
) -> str:
    """
    Get the URI for a place photo.

    Args:
        photo_resource_name: Photo resource name from Place data
            (e.g. "places/ChIJ.../photos/...")
        max_width: Maximum width in pixels (1-4800)
        max_height: Maximum height in pixels (1-4800)
        account: Account for authentication

    Returns:
        Photo URI string that can be used to fetch the image.
    """
    photo_resource_name = validate_photo_resource_name(photo_resource_name)
    max_width = validate_photo_max_dimension(max_width, "max_width")
    max_height = validate_photo_max_dimension(max_height, "max_height")

    acct_key = account or "default"
    rate_limiter.check(acct_key, "photo")

    try:
        session = _get_session(account)
        url = (
            f"{PLACES_API_BASE}/{photo_resource_name}/media"
            f"?maxWidthPx={max_width}&maxHeightPx={max_height}"
            f"&skipHttpRedirect=true"
        )

        resp = session.get(url)

        if resp.status_code != 200:
            error_body = resp.text[:500]
            msg = f"Places API error ({resp.status_code}): {error_body}"
            raise RuntimeError(msg)

        data = resp.json()
        photo_uri = data.get("photoUri", "")

        audit_log(
            "photo",
            acct_key,
            {
                "photo": photo_resource_name,
            },
        )

        return photo_uri

    except SecurityError:
        raise
    except Exception as e:
        audit_log(
            "photo",
            acct_key,
            {
                "photo": photo_resource_name,
                "error": sanitize_error_message(e),
            },
            success=False,
        )
        raise RuntimeError(sanitize_error_message(e)) from None


# ---------------------------------------------------------------------------
# Convenience: Search with filters
# ---------------------------------------------------------------------------


def search_with_filters(
    query: str,
    *,
    price_levels: list[str] | None = None,
    min_rating: float | None = None,
    open_now: bool = False,
    included_type: str | None = None,
    max_results: int = 10,
    language_code: str | None = None,
    region_code: str | None = None,
    location_bias_lat: float | None = None,
    location_bias_lng: float | None = None,
    location_bias_radius: float | None = None,
    account: str | None = None,
) -> list[Place]:
    """
    Search for places with advanced filters.

    Convenience wrapper around text_search with commonly used filter
    combinations for AI agent use.
    """
    return text_search(
        query,
        included_type=included_type,
        max_results=max_results,
        language_code=language_code,
        region_code=region_code,
        location_bias_lat=location_bias_lat,
        location_bias_lng=location_bias_lng,
        location_bias_radius=location_bias_radius,
        open_now=open_now if open_now else None,
        min_rating=min_rating,
        price_levels=price_levels,
        account=account,
    )


# ---------------------------------------------------------------------------
# Convenience: Find nearby services (smart home use case)
# ---------------------------------------------------------------------------


def find_nearby_services(
    service_type: str,
    latitude: float,
    longitude: float,
    radius: float = 5000.0,
    *,
    max_results: int = 10,
    language_code: str | None = None,
    account: str | None = None,
) -> list[Place]:
    """
    Find service providers near a location.

    Designed for smart home / personal assistant use cases:
    plumbers, electricians, locksmiths, HVAC technicians, etc.

    Args:
        service_type: Type of service (e.g. "plumber", "electrician")
        latitude: Home/target latitude
        longitude: Home/target longitude
        radius: Search radius in meters (default 5000)
        max_results: Number of results
        language_code: BCP-47 language code
        account: Account for authentication

    Returns:
        List of places offering the requested service.
    """
    return text_search(
        f"{service_type}",
        max_results=max_results,
        language_code=language_code,
        location_bias_lat=latitude,
        location_bias_lng=longitude,
        location_bias_radius=radius,
        field_mask=FIELD_MASK_STANDARD,
        account=account,
    )


# ---------------------------------------------------------------------------
# Convenience: Find EV chargers
# ---------------------------------------------------------------------------


def find_ev_chargers(
    latitude: float,
    longitude: float,
    radius: float = 5000.0,
    *,
    connector_types: list[str] | None = None,
    min_charging_rate_kw: float | None = None,
    max_results: int = 10,
    language_code: str | None = None,
    account: str | None = None,
) -> list[Place]:
    """
    Find EV charging stations near a location.

    Args:
        latitude: Center latitude
        longitude: Center longitude
        radius: Search radius in meters (default 5000)
        connector_types: EV connector type filter
        min_charging_rate_kw: Minimum charging rate in kW
        language_code: BCP-47 language code
        account: Account for authentication

    Returns:
        List of EV charging stations with availability info.
    """
    latitude = validate_latitude(latitude)
    longitude = validate_longitude(longitude)
    radius = validate_radius(radius)
    max_results = validate_max_results(max_results)

    if connector_types:
        connector_types = validate_ev_connector_types(connector_types)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "text_search")

    body: dict[str, Any] = {
        "textQuery": "EV charging station",
        "pageSize": max_results,
        "locationBias": {
            "circle": {
                "center": {"latitude": latitude, "longitude": longitude},
                "radius": radius,
            }
        },
    }

    if language_code:
        body["languageCode"] = validate_language_code(language_code)

    ev_options: dict[str, Any] = {}
    if connector_types:
        ev_options["connectorTypes"] = connector_types
    if min_charging_rate_kw is not None:
        if min_charging_rate_kw < 0:
            msg = "Minimum charging rate must be non-negative"
            raise SecurityError(msg)
        ev_options["minimumChargingRateKw"] = min_charging_rate_kw
    if ev_options:
        body["evOptions"] = ev_options

    # Include EV-specific fields
    mask = (
        f"{FIELD_MASK_BASIC},"
        "places.evChargeOptions,places.rating,places.userRatingCount,"
        "places.regularOpeningHours,places.businessStatus,"
        "places.websiteUri,places.googleMapsUri"
    )

    try:
        data = _api_post("places:searchText", body, mask, account)

        places = []
        for place_data in data.get("places", []):
            places.append(_parse_place(place_data))

        audit_log(
            "find_ev_chargers",
            acct_key,
            {
                "location": f"{latitude},{longitude}",
                "results": len(places),
            },
        )

        return places

    except SecurityError:
        raise
    except Exception as e:
        audit_log(
            "find_ev_chargers",
            acct_key,
            {
                "error": sanitize_error_message(e),
            },
            success=False,
        )
        raise RuntimeError(sanitize_error_message(e)) from None
