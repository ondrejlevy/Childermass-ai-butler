"""
Security utilities for Places MCP server.

Provides input validation, sanitization, rate limiting, and audit logging
for all Google Places API (New) operations.
"""

import json
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any


class SecurityError(Exception):
    """Raised when security validation fails."""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum lengths
MAX_QUERY_LENGTH = 2048
MAX_PLACE_ID_LENGTH = 300
MAX_TYPE_LENGTH = 100
MAX_LANGUAGE_CODE_LENGTH = 10
MAX_REGION_CODE_LENGTH = 5
MAX_FIELD_MASK_LENGTH = 2000
MAX_AUTOCOMPLETE_INPUT_LENGTH = 500

# Coordinate ranges
MIN_LATITUDE = -90.0
MAX_LATITUDE = 90.0
MIN_LONGITUDE = -180.0
MAX_LONGITUDE = 180.0

# Radius limits (meters)
MIN_RADIUS = 0.0
MAX_RADIUS = 50000.0

# Search result limits
MIN_RESULTS = 1
MAX_RESULTS = 20

# Price levels (Google Places API)
VALID_PRICE_LEVELS = {
    "PRICE_LEVEL_FREE",
    "PRICE_LEVEL_INEXPENSIVE",
    "PRICE_LEVEL_MODERATE",
    "PRICE_LEVEL_EXPENSIVE",
    "PRICE_LEVEL_VERY_EXPENSIVE",
}

# Price levels allowed in request (FREE is response-only)
VALID_REQUEST_PRICE_LEVELS = VALID_PRICE_LEVELS - {"PRICE_LEVEL_FREE"}

# Rank preferences
VALID_RANK_PREFERENCES = {"RELEVANCE", "DISTANCE", "POPULARITY"}

# EV connector types
VALID_EV_CONNECTOR_TYPES = {
    "EV_CONNECTOR_TYPE_UNSPECIFIED",
    "EV_CONNECTOR_TYPE_OTHER",
    "EV_CONNECTOR_TYPE_J1772",
    "EV_CONNECTOR_TYPE_TYPE_2",
    "EV_CONNECTOR_TYPE_CHADEMO",
    "EV_CONNECTOR_TYPE_CCS_COMBO_1",
    "EV_CONNECTOR_TYPE_CCS_COMBO_2",
    "EV_CONNECTOR_TYPE_TESLA",
    "EV_CONNECTOR_TYPE_UNSPECIFIED_GB_T",
    "EV_CONNECTOR_TYPE_UNSPECIFIED_WALL_OUTLET",
}

# Place types from Google Table A (commonly used subset for validation)
# Full list: https://developers.google.com/maps/documentation/places/web-service/place-types
VALID_PLACE_TYPES: set[str] = {
    # Automotive
    "car_dealer",
    "car_rental",
    "car_repair",
    "car_wash",
    "electric_vehicle_charging_station",
    "gas_station",
    "parking",
    "rest_stop",
    # Business
    "farm",
    # Culture
    "art_gallery",
    "museum",
    "performing_arts_theater",
    # Education
    "library",
    "preschool",
    "primary_school",
    "school",
    "secondary_school",
    "university",
    # Entertainment & recreation
    "amusement_center",
    "amusement_park",
    "aquarium",
    "banquet_hall",
    "bowling_alley",
    "casino",
    "community_center",
    "convention_center",
    "cultural_center",
    "dog_park",
    "event_venue",
    "hiking_area",
    "historical_landmark",
    "marina",
    "movie_rental",
    "movie_theater",
    "national_park",
    "night_club",
    "park",
    "tourist_attraction",
    "visitor_center",
    "wedding_venue",
    "zoo",
    # Finance
    "accounting",
    "atm",
    "bank",
    # Food & drink
    "american_restaurant",
    "bakery",
    "bar",
    "barbecue_restaurant",
    "brazilian_restaurant",
    "breakfast_restaurant",
    "brunch_restaurant",
    "cafe",
    "chinese_restaurant",
    "coffee_shop",
    "fast_food_restaurant",
    "french_restaurant",
    "greek_restaurant",
    "hamburger_restaurant",
    "ice_cream_shop",
    "indian_restaurant",
    "indonesian_restaurant",
    "italian_restaurant",
    "japanese_restaurant",
    "korean_restaurant",
    "lebanese_restaurant",
    "meal_delivery",
    "meal_takeaway",
    "mediterranean_restaurant",
    "mexican_restaurant",
    "middle_eastern_restaurant",
    "pizza_restaurant",
    "ramen_restaurant",
    "restaurant",
    "sandwich_shop",
    "seafood_restaurant",
    "spanish_restaurant",
    "steak_house",
    "sushi_restaurant",
    "thai_restaurant",
    "turkish_restaurant",
    "vegan_restaurant",
    "vegetarian_restaurant",
    "vietnamese_restaurant",
    # Government
    "city_hall",
    "courthouse",
    "embassy",
    "fire_station",
    "local_government_office",
    "police",
    "post_office",
    # Health & wellness
    "dental_clinic",
    "dentist",
    "doctor",
    "drugstore",
    "hospital",
    "medical_lab",
    "pharmacy",
    "physiotherapist",
    "spa",
    # Lodging
    "bed_and_breakfast",
    "campground",
    "camping_cabin",
    "cottage",
    "extended_stay_hotel",
    "farmstay",
    "guest_house",
    "hostel",
    "hotel",
    "lodging",
    "motel",
    "private_guest_room",
    "resort_hotel",
    "rv_park",
    # Places of worship
    "church",
    "hindu_temple",
    "mosque",
    "synagogue",
    # Services
    "barber_shop",
    "beauty_salon",
    "cemetery",
    "child_care_agency",
    "consultant",
    "courier_service",
    "electrician",
    "florist",
    "funeral_home",
    "hair_care",
    "hair_salon",
    "insurance_agency",
    "laundry",
    "lawyer",
    "locksmith",
    "moving_company",
    "painter",
    "plumber",
    "real_estate_agency",
    "roofing_contractor",
    "storage",
    "tailor",
    "telecommunications_service_provider",
    "travel_agency",
    "veterinary_care",
    # Shopping
    "auto_parts_store",
    "bicycle_store",
    "book_store",
    "cell_phone_store",
    "clothing_store",
    "convenience_store",
    "department_store",
    "discount_store",
    "electronics_store",
    "furniture_store",
    "gift_shop",
    "grocery_store",
    "hardware_store",
    "home_goods_store",
    "home_improvement_store",
    "jewelry_store",
    "liquor_store",
    "market",
    "pet_store",
    "shoe_store",
    "shopping_mall",
    "sporting_goods_store",
    "store",
    "supermarket",
    "wholesaler",
    # Sports
    "athletic_field",
    "fitness_center",
    "golf_course",
    "gym",
    "playground",
    "ski_resort",
    "sports_club",
    "sports_complex",
    "stadium",
    "swimming_pool",
    # Transportation
    "airport",
    "bus_station",
    "bus_stop",
    "ferry_terminal",
    "heliport",
    "light_rail_station",
    "park_and_ride",
    "subway_station",
    "taxi_stand",
    "train_station",
    "transit_depot",
    "transit_station",
    "truck_stop",
}

# Field masks – commonly used sets for convenience
FIELD_MASK_BASIC = (
    "places.id,places.displayName,places.formattedAddress,"
    "places.location,places.types,places.primaryType"
)
FIELD_MASK_STANDARD = (
    f"{FIELD_MASK_BASIC},"
    "places.rating,places.userRatingCount,places.priceLevel,"
    "places.businessStatus,places.websiteUri,"
    "places.internationalPhoneNumber,places.regularOpeningHours,"
    "places.photos,places.googleMapsUri"
)
FIELD_MASK_DETAILED = (
    f"{FIELD_MASK_STANDARD},"
    "places.editorialSummary,places.reviews,places.reviewSummary,"
    "places.accessibilityOptions,places.paymentOptions,"
    "places.parkingOptions,places.delivery,places.dineIn,"
    "places.takeout,places.reservable,places.servesBreakfast,"
    "places.servesLunch,places.servesDinner,places.servesBeer,"
    "places.servesWine,places.servesCocktails,places.servesVegetarianFood,"
    "places.outdoorSeating,places.goodForChildren,places.goodForGroups,"
    "places.allowsDogs,places.restroom"
)

# Detail field masks (without places. prefix – used for Place Details)
DETAIL_FIELD_MASK_BASIC = "id,displayName,formattedAddress,location,types,primaryType"
DETAIL_FIELD_MASK_STANDARD = (
    f"{DETAIL_FIELD_MASK_BASIC},"
    "rating,userRatingCount,priceLevel,businessStatus,websiteUri,"
    "internationalPhoneNumber,regularOpeningHours,photos,googleMapsUri"
)
DETAIL_FIELD_MASK_DETAILED = (
    f"{DETAIL_FIELD_MASK_STANDARD},"
    "editorialSummary,reviews,reviewSummary,"
    "accessibilityOptions,paymentOptions,parkingOptions,"
    "delivery,dineIn,takeout,reservable,"
    "servesBreakfast,servesLunch,servesDinner,"
    "servesBeer,servesWine,servesCocktails,servesVegetarianFood,"
    "outdoorSeating,goodForChildren,goodForGroups,"
    "allowsDogs,restroom"
)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def validate_place_id(place_id: str) -> str:
    """
    Validate a Google Place ID.

    Place IDs are alphanumeric strings typically starting with 'ChIJ'.
    Returns the validated place ID.  Raises SecurityError on invalid input.
    """
    if not place_id or not isinstance(place_id, str):
        msg = "Place ID is required"
        raise SecurityError(msg)

    place_id = place_id.strip()

    if any(c in place_id for c in ["\n", "\r", "\0", "\t"]):
        msg = "Place ID contains invalid control characters"
        raise SecurityError(msg)

    if len(place_id) > MAX_PLACE_ID_LENGTH:
        msg = f"Place ID too long: {len(place_id)} chars (max {MAX_PLACE_ID_LENGTH})"
        raise SecurityError(msg)

    # Place IDs are typically base64-url-safe + some special chars
    if not re.match(r"^[A-Za-z0-9_\-]+$", place_id):
        msg = f"Invalid Place ID format: {place_id}"
        raise SecurityError(msg)

    return place_id


def validate_query(query: str) -> str:
    """
    Validate a search query string.

    Returns the validated query.  Raises SecurityError on invalid input.
    """
    if not query or not isinstance(query, str):
        msg = "Search query is required"
        raise SecurityError(msg)

    query = query.strip()

    if any(c in query for c in ["\0", chr(0x1B)]):
        msg = "Query contains invalid control characters"
        raise SecurityError(msg)

    if len(query) > MAX_QUERY_LENGTH:
        msg = f"Query too long: {len(query)} chars (max {MAX_QUERY_LENGTH})"
        raise SecurityError(msg)

    return query


def validate_autocomplete_input(text: str) -> str:
    """
    Validate autocomplete input text.

    Returns the validated input.  Raises SecurityError on invalid input.
    """
    if not text or not isinstance(text, str):
        msg = "Autocomplete input is required"
        raise SecurityError(msg)

    text = text.strip()

    if any(c in text for c in ["\0", chr(0x1B)]):
        msg = "Input contains invalid control characters"
        raise SecurityError(msg)

    if len(text) > MAX_AUTOCOMPLETE_INPUT_LENGTH:
        msg = f"Input too long: {len(text)} chars (max {MAX_AUTOCOMPLETE_INPUT_LENGTH})"
        raise SecurityError(msg)

    return text


def validate_latitude(lat: float) -> float:
    """Validate a latitude value.  Must be between -90 and 90."""
    if not isinstance(lat, (int, float)):
        msg = f"Latitude must be a number, got {type(lat)}"
        raise SecurityError(msg)

    lat = float(lat)
    if lat < MIN_LATITUDE or lat > MAX_LATITUDE:
        msg = f"Latitude out of range: {lat} (must be {MIN_LATITUDE} to {MAX_LATITUDE})"
        raise SecurityError(msg)

    return lat


def validate_longitude(lng: float) -> float:
    """Validate a longitude value.  Must be between -180 and 180."""
    if not isinstance(lng, (int, float)):
        msg = f"Longitude must be a number, got {type(lng)}"
        raise SecurityError(msg)

    lng = float(lng)
    if lng < MIN_LONGITUDE or lng > MAX_LONGITUDE:
        msg = f"Longitude out of range: {lng} (must be {MIN_LONGITUDE} to {MAX_LONGITUDE})"
        raise SecurityError(msg)

    return lng


def validate_radius(radius: float) -> float:
    """
    Validate a search radius in meters.

    Must be between 0 and 50000 (inclusive).
    """
    if not isinstance(radius, (int, float)):
        msg = f"Radius must be a number, got {type(radius)}"
        raise SecurityError(msg)

    radius = float(radius)
    if radius < MIN_RADIUS or radius > MAX_RADIUS:
        msg = f"Radius out of range: {radius} m (must be {MIN_RADIUS} to {MAX_RADIUS})"
        raise SecurityError(msg)

    return radius


def validate_max_results(count: int) -> int:
    """Validate the max results count.  Must be 1-20."""
    if not isinstance(count, int):
        msg = f"Max results must be an integer, got {type(count)}"
        raise SecurityError(msg)

    if count < MIN_RESULTS or count > MAX_RESULTS:
        msg = f"Max results out of range: {count} (must be {MIN_RESULTS} to {MAX_RESULTS})"
        raise SecurityError(msg)

    return count


def validate_place_type(type_: str) -> str:
    """
    Validate a place type against the known set.

    Returns the validated type.  Raises SecurityError if unknown.
    """
    if not type_ or not isinstance(type_, str):
        msg = "Place type is required"
        raise SecurityError(msg)

    type_ = type_.strip().lower()

    if any(c in type_ for c in ["\n", "\r", "\0"]):
        msg = "Place type contains invalid control characters"
        raise SecurityError(msg)

    if len(type_) > MAX_TYPE_LENGTH:
        msg = f"Place type too long: {len(type_)} chars"
        raise SecurityError(msg)

    if type_ not in VALID_PLACE_TYPES:
        msg = (
            f"Unknown place type: {type_!r}. "
            "See: https://developers.google.com/maps/documentation/"
            "places/web-service/place-types"
        )
        raise SecurityError(msg)

    return type_


def validate_place_types(types: list[str]) -> list[str]:
    """Validate a list of place types.  Returns list of validated types."""
    if not types:
        return []
    return [validate_place_type(t) for t in types]


def validate_language_code(code: str) -> str:
    """Validate a BCP-47 language code."""
    if not code or not isinstance(code, str):
        msg = "Language code is required"
        raise SecurityError(msg)

    code = code.strip().lower()

    if len(code) > MAX_LANGUAGE_CODE_LENGTH:
        msg = f"Language code too long: {code}"
        raise SecurityError(msg)

    # Basic BCP-47 pattern: 2-3 letter language, optional region
    if not re.match(r"^[a-z]{2,3}(-[a-z]{2,4})?$", code):
        msg = f"Invalid language code format: {code}"
        raise SecurityError(msg)

    return code


def validate_region_code(code: str) -> str:
    """Validate a CLDR region code (2-char)."""
    if not code or not isinstance(code, str):
        msg = "Region code is required"
        raise SecurityError(msg)

    code = code.strip().lower()

    if len(code) > MAX_REGION_CODE_LENGTH:
        msg = f"Region code too long: {code}"
        raise SecurityError(msg)

    if not re.match(r"^[a-z]{2}$", code):
        msg = f"Invalid region code format: {code}"
        raise SecurityError(msg)

    return code


def validate_price_levels(levels: list[str]) -> list[str]:
    """Validate a list of price levels."""
    if not levels:
        return []

    validated = []
    for level in levels:
        level = level.strip().upper()
        if level not in VALID_REQUEST_PRICE_LEVELS:
            msg = (
                f"Invalid price level: {level!r}. "
                f"Valid values: {sorted(VALID_REQUEST_PRICE_LEVELS)}"
            )
            raise SecurityError(msg)
        validated.append(level)

    return validated


def validate_rank_preference(pref: str) -> str:
    """Validate a rank preference value."""
    if not pref or not isinstance(pref, str):
        msg = "Rank preference is required"
        raise SecurityError(msg)

    pref = pref.strip().upper()

    if pref not in VALID_RANK_PREFERENCES:
        msg = f"Invalid rank preference: {pref!r}. Valid values: {sorted(VALID_RANK_PREFERENCES)}"
        raise SecurityError(msg)

    return pref


def validate_min_rating(rating: float) -> float:
    """Validate a minimum rating filter (0.0 to 5.0, in 0.5 steps)."""
    if not isinstance(rating, (int, float)):
        msg = f"Rating must be a number, got {type(rating)}"
        raise SecurityError(msg)

    rating = float(rating)
    if rating < 0.0 or rating > 5.0:
        msg = f"Rating out of range: {rating} (must be 0.0 to 5.0)"
        raise SecurityError(msg)

    return rating


def validate_ev_connector_types(types: list[str]) -> list[str]:
    """Validate a list of EV connector types."""
    if not types:
        return []

    validated = []
    for t in types:
        t = t.strip().upper()
        if t not in VALID_EV_CONNECTOR_TYPES:
            msg = (
                f"Invalid EV connector type: {t!r}. "
                f"Valid values: {sorted(VALID_EV_CONNECTOR_TYPES)}"
            )
            raise SecurityError(msg)
        validated.append(t)

    return validated


def validate_photo_resource_name(name: str) -> str:
    """
    Validate a photo resource name.

    Format: places/{place_id}/photos/{photo_id}
    """
    if not name or not isinstance(name, str):
        msg = "Photo resource name is required"
        raise SecurityError(msg)

    name = name.strip()

    if any(c in name for c in ["\n", "\r", "\0"]):
        msg = "Photo resource name contains invalid control characters"
        raise SecurityError(msg)

    if len(name) > 500:
        msg = "Photo resource name too long"
        raise SecurityError(msg)

    # Must match pattern: places/{id}/photos/{id}
    if not re.match(r"^places/[A-Za-z0-9_\-]+/photos/[A-Za-z0-9_\-/=]+$", name):
        msg = f"Invalid photo resource name format: {name}"
        raise SecurityError(msg)

    return name


def validate_photo_max_dimension(value: int, name: str = "dimension") -> int:
    """Validate a photo max width or height (1-4800 pixels)."""
    if not isinstance(value, int):
        msg = f"Photo {name} must be an integer"
        raise SecurityError(msg)

    if value < 1 or value > 4800:
        msg = f"Photo {name} out of range: {value} (must be 1 to 4800)"
        raise SecurityError(msg)

    return value


# ---------------------------------------------------------------------------
# Error sanitization
# ---------------------------------------------------------------------------


def sanitize_error_message(error: Exception) -> str:
    """
    Sanitize error message to prevent credential / key leaks.
    """
    msg = str(error)

    patterns = [
        (r"(password|token|key|secret|credential)[\s:=]+\S+", r"\1=***"),
        (r"Bearer \S+", "Bearer ***"),
        (r"ya29\.\S+", "ya29.***"),  # Google access tokens
        (r"1//[A-Za-z0-9_-]+", "1//***"),  # Google refresh tokens
        (r"AIza[A-Za-z0-9_\-]+", "AIza***"),  # Google API keys
        (r"/[\w\-\.]+/[\w\-\.]+\.json", "/***/credentials.json"),
        (r"X-Goog-Api-Key:\s*\S+", "X-Goog-Api-Key: ***"),
    ]

    for pattern, replacement in patterns:
        msg = re.sub(pattern, replacement, msg, flags=re.IGNORECASE)

    return msg


# ---------------------------------------------------------------------------
# Rate Limiting (Token Bucket Algorithm)
# ---------------------------------------------------------------------------


@dataclass
class _Bucket:
    """Token bucket for rate limiting."""

    tokens: float
    last_refill: float
    capacity: int
    refill_rate: float  # tokens per second


class RateLimiter:
    """
    Thread-safe per-account, per-operation rate limiter.

    Default limits (per minute):
      - text_search:     60
      - nearby_search:   60
      - place_details:   60
      - autocomplete:   120
      - photo:           30
    """

    DEFAULT_LIMITS: dict[str, tuple[int, float]] = {
        # (capacity, refill_rate tokens/sec)
        "text_search": (60, 60 / 60),
        "nearby_search": (60, 60 / 60),
        "place_details": (60, 60 / 60),
        "autocomplete": (120, 120 / 60),
        "photo": (30, 30 / 60),
    }

    def __init__(self) -> None:
        self._buckets: dict[str, _Bucket] = {}
        self._lock = Lock()

    def _key(self, account: str, operation: str) -> str:
        return f"{account}:{operation}"

    def allow(self, account: str, operation: str) -> bool:
        """
        Check if operation is allowed under rate limits.

        Returns True and consumes a token, or False if rate-limited.
        """
        key = self._key(account, operation)
        capacity, refill_rate = self.DEFAULT_LIMITS.get(operation, (60, 1.0))

        with self._lock:
            now = time.monotonic()

            if key not in self._buckets:
                self._buckets[key] = _Bucket(
                    tokens=capacity - 1,
                    last_refill=now,
                    capacity=capacity,
                    refill_rate=refill_rate,
                )
                return True

            bucket = self._buckets[key]

            # Refill tokens
            elapsed = now - bucket.last_refill
            bucket.tokens = min(
                bucket.capacity,
                bucket.tokens + elapsed * bucket.refill_rate,
            )
            bucket.last_refill = now

            if bucket.tokens >= 1:
                bucket.tokens -= 1
                return True

            return False

    def check(self, account: str, operation: str) -> None:
        """Like allow() but raises SecurityError on rate limit."""
        if not self.allow(account, operation):
            msg = f"Rate limit exceeded for {operation}. Please wait before retrying."
            raise SecurityError(msg)


# Module-level singleton
rate_limiter = RateLimiter()


# ---------------------------------------------------------------------------
# Audit Logging
# ---------------------------------------------------------------------------

_AUDIT_DIR = Path.home() / ".childermass"
_AUDIT_LOG_FILE = _AUDIT_DIR / "places-audit.log"


def _get_audit_logger() -> logging.Logger:
    """Get or create the audit logger (lazy init)."""
    audit = logging.getLogger("childermass.places_mcp.audit")
    if not audit.handlers:
        _AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        from logging.handlers import RotatingFileHandler

        handler = RotatingFileHandler(
            str(_AUDIT_LOG_FILE),
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        audit.addHandler(handler)
        audit.setLevel(logging.INFO)
        audit.propagate = False
    return audit


def audit_log(
    operation: str,
    account: str = "",
    details: dict[str, Any] | None = None,
    success: bool = True,
) -> None:
    """
    Write a structured audit log entry.

    Args:
        operation: Operation name (e.g. "text_search", "place_details")
        account: Account identifier used
        details: Additional context (sanitised – no credentials!)
        success: Whether the operation succeeded
    """
    audit = _get_audit_logger()

    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "operation": operation,
        "account": account,
        "success": success,
    }
    if details:
        entry["details"] = details

    try:
        audit.info(json.dumps(entry, ensure_ascii=False))
    except Exception:
        pass  # Audit logging must never crash the server
