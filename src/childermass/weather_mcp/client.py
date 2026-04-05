"""OpenWeatherMap API client for Childermass Weather MCP.

This module provides a Python wrapper around the OpenWeatherMap API with
input validation, rate limiting, response caching, and audit logging.
"""

import time
from dataclasses import dataclass
from typing import Any

import requests

from .auth import get_api_key
from .security import (
    SecurityError,
    audit_log,
    rate_limiter,
    sanitize_error_message,
    validate_city_name,
    validate_days,
    validate_location,
    validate_units,
)


# OpenWeatherMap API configuration
BASE_URL = "https://api.openweathermap.org/data/2.5"
GEO_URL = "https://api.openweathermap.org/geo/1.0"
CACHE_TTL = 900  # 15 minutes in seconds


# ============================================================================
# Data Models
# ============================================================================


@dataclass
class Coordinates:
    """Geographic coordinates."""

    latitude: float
    longitude: float
    name: str | None = None
    country: str | None = None


@dataclass
class WeatherCondition:
    """Current weather condition."""

    id: int
    main: str  # e.g., "Rain", "Clear"
    description: str  # e.g., "light rain"
    icon: str


@dataclass
class CurrentWeather:
    """Current weather data."""

    temperature: float
    feels_like: float
    temp_min: float
    temp_max: float
    pressure: int
    humidity: int
    visibility: int | None
    wind_speed: float
    wind_deg: int | None
    clouds: int
    conditions: list[WeatherCondition]
    timestamp: int
    sunrise: int | None
    sunset: int | None
    timezone: int | None
    location_name: str


@dataclass
class ForecastPoint:
    """Single forecast data point (3-hour interval)."""

    timestamp: int
    datetime_text: str
    temperature: float
    feels_like: float
    temp_min: float
    temp_max: float
    pressure: int
    humidity: int
    conditions: list[WeatherCondition]
    clouds: int
    wind_speed: float
    wind_deg: int | None
    visibility: int | None
    pop: float  # Probability of precipitation (0-1)
    rain_3h: float | None  # Rain volume for last 3h (mm)
    snow_3h: float | None  # Snow volume for last 3h (mm)


@dataclass
class DailyForecast:
    """Daily aggregated forecast."""

    date: str  # YYYY-MM-DD
    temp_min: float
    temp_max: float
    temp_avg: float
    conditions: str  # Most common condition
    pop_max: float  # Maximum precipitation probability


@dataclass
class WeatherAlert:
    """Weather alert/warning."""

    sender_name: str
    event: str
    start: int
    end: int
    description: str
    tags: list[str]


@dataclass
class AirQuality:
    """Air quality data."""

    aqi: int  # Air Quality Index (1-5, 1=Good, 5=Very Poor)
    co: float  # Carbon monoxide (μg/m³)
    no: float  # Nitrogen monoxide (μg/m³)
    no2: float  # Nitrogen dioxide (μg/m³)
    o3: float  # Ozone (μg/m³)
    so2: float  # Sulphur dioxide (μg/m³)
    pm2_5: float  # Fine particulate matter (μg/m³)
    pm10: float  # Coarse particulate matter (μg/m³)
    timestamp: int


# ============================================================================
# Response Cache
# ============================================================================


class ResponseCache:
    """Simple in-memory cache with TTL."""

    def __init__(self, ttl: int = CACHE_TTL):
        """Initialize cache.

        Args:
            ttl: Time-to-live in seconds
        """
        self.ttl = ttl
        self.cache: dict[str, tuple[Any, float]] = {}

    def get(self, key: str) -> Any | None:
        """Get cached value if not expired.

        Args:
            key: Cache key

        Returns:
            Cached value or None if expired/missing
        """
        if key in self.cache:
            value, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                return value
            # Expired, remove from cache
            del self.cache[key]
        return None

    def set(self, key: str, value: Any) -> None:
        """Store value in cache with current timestamp.

        Args:
            key: Cache key
            value: Value to cache
        """
        self.cache[key] = (value, time.time())

    def clear(self) -> None:
        """Clear all cached data."""
        self.cache.clear()


# ============================================================================
# Weather Client
# ============================================================================


class WeatherClient:
    """OpenWeatherMap API client with caching and security."""

    def __init__(self, api_key: str | None = None, cache_ttl: int = CACHE_TTL):
        """Initialize weather client.

        Args:
            api_key: OpenWeatherMap API key (if None, will load from auth)
            cache_ttl: Cache time-to-live in seconds
        """
        if api_key is None:
            api_key = get_api_key()
        self.api_key = api_key
        self.cache = ResponseCache(ttl=cache_ttl)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Childermass-Weather-MCP/0.1.0"})

    def _make_request(self, endpoint: str, params: dict[str, Any]) -> Any:
        """Make API request with error handling.

        Args:
            endpoint: API endpoint URL
            params: Query parameters

        Returns:
            JSON response (dict or list)

        Raises:
            SecurityError: On API errors or network issues
        """
        # Add API key to params
        params["appid"] = self.api_key

        try:
            response = self.session.get(endpoint, params=params, timeout=10)
            try:
                response.raise_for_status()
            except Exception as e:
                # Some tests/mocks raise generic Exception from raise_for_status();
                # inspect response.status_code when available and map to friendly
                # messages.
                status = getattr(response, "status_code", None)
                if status == 401:
                    msg = "Invalid API key. Please check your OpenWeatherMap API key."
                    raise SecurityError(msg)
                if status == 404:
                    msg = "Location not found. Please check the city name or coordinates."
                    raise SecurityError(msg)
                if status == 429:
                    msg = "API rate limit exceeded. Please try again later."
                    raise SecurityError(msg)
                # Fall back to the original exception message
                msg = f"HTTP error: {sanitize_error_message(e)}"
                raise SecurityError(msg) from e

            return response.json()
        except requests.exceptions.RequestException as e:
            msg = f"Network error: {sanitize_error_message(e)}"
            raise SecurityError(msg) from e

    def geocode_city(self, city_name: str) -> Coordinates:
        """Convert city name to coordinates using geocoding API.

        Args:
            city_name: City name, optionally with country code (e.g., "London,UK")

        Returns:
            Coordinates: Geographic coordinates for the city

        Raises:
            SecurityError: If geocoding fails
        """
        # Validate input
        city_name = validate_city_name(city_name)

        # Check rate limit
        rate_limiter.check("geocode")

        # Check cache
        cache_key = f"geocode:{city_name}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            audit_log("geocode_city", city_name, {"cached": True})
            # Type guard for cached value
            if not isinstance(cached, Coordinates):
                msg = "Invalid cached coordinates"
                raise SecurityError(msg)
            return cached

        # Make API request
        endpoint = f"{GEO_URL}/direct"
        params = {"q": city_name, "limit": 1}

        try:
            data = self._make_request(endpoint, params)

            if not data:
                msg = f"City not found: {city_name}"
                raise SecurityError(msg)

            result = data[0]
            coords = Coordinates(
                latitude=result["lat"],
                longitude=result["lon"],
                name=result.get("name"),
                country=result.get("country"),
            )

            # Cache result
            self.cache.set(cache_key, coords)

            # Audit log
            audit_log(
                "geocode_city",
                city_name,
                {
                    "lat": coords.latitude,
                    "lon": coords.longitude,
                    "cached": False,
                },
            )

            return coords
        except SecurityError:
            raise
        except Exception as e:
            msg = f"Geocoding failed: {sanitize_error_message(e)}"
            raise SecurityError(msg)

    def get_current_weather(
        self, location: str | tuple[float, float], units: str = "metric"
    ) -> CurrentWeather:
        """Get current weather for a location.

        Args:
            location: City name or (latitude, longitude) tuple
            units: Temperature units ("metric", "imperial", "standard")

        Returns:
            CurrentWeather: Current weather data

        Raises:
            SecurityError: If request fails
        """
        # Validate inputs
        loc_type, city, lat, lon = validate_location(location)
        units = validate_units(units)

        # If location is a city name, allow city names that include digits
        # (some callers/tests use alphanumeric names) and use the weather
        # endpoint's `q` parameter directly instead of performing a separate
        # geocode lookup.
        if loc_type == "city":
            # Re-validate city name allowing  digits for API queries
            if city is None:
                msg = "City name is required for city location type"
                raise SecurityError(msg)
            city = validate_city_name(city, allow_digits=True)
            location_str = city
            cache_key = f"current:q:{city}:{units}"
            params = {"q": city, "units": units}
        else:
            location_str = f"{lat},{lon}"
            cache_key = f"current:{lat},{lon}:{units}"
            params = {"lat": str(lat), "lon": str(lon), "units": units}

        # Check rate limit
        rate_limiter.check("current")

        # Check cache
        cached = self.cache.get(cache_key)
        if cached is not None:
            audit_log("get_current_weather", location_str or "", {"cached": True})
            # Type guard for cached value
            if not isinstance(cached, CurrentWeather):
                msg = "Invalid cached weather data"
                raise SecurityError(msg)
            return cached

        # Make API request
        endpoint = f"{BASE_URL}/weather"

        try:
            data = self._make_request(endpoint, params)

            # Parse response
            weather = CurrentWeather(
                temperature=data["main"]["temp"],
                feels_like=data["main"]["feels_like"],
                temp_min=data["main"]["temp_min"],
                temp_max=data["main"]["temp_max"],
                pressure=data["main"]["pressure"],
                humidity=data["main"]["humidity"],
                visibility=data.get("visibility"),
                wind_speed=data["wind"]["speed"],
                wind_deg=data["wind"].get("deg"),
                clouds=data["clouds"]["all"],
                conditions=[
                    WeatherCondition(
                        id=w["id"],
                        main=w["main"],
                        description=w["description"],
                        icon=w["icon"],
                    )
                    for w in data["weather"]
                ],
                timestamp=data["dt"],
                sunrise=data["sys"].get("sunrise"),
                sunset=data["sys"].get("sunset"),
                timezone=data.get("timezone"),
                location_name=data["name"],
            )

            # Cache result
            self.cache.set(cache_key, weather)

            # Audit log
            audit_log(
                "get_current_weather",
                location_str or "",
                {
                    "temp": weather.temperature,
                    "conditions": weather.conditions[0].main if weather.conditions else None,
                    "cached": False,
                },
            )

            return weather
        except SecurityError:
            raise
        except Exception as e:
            msg = f"Failed to get current weather: {sanitize_error_message(e)}"
            raise SecurityError(msg)

    def get_forecast(
        self, location: str | tuple[float, float], days: int = 5, units: str = "metric"
    ) -> list[ForecastPoint]:
        """Get weather forecast for a location.

        Args:
            location: City name or (latitude, longitude) tuple
            days: Number of days to forecast (1-5)
            units: Temperature units ("metric", "imperial", "standard")

        Returns:
            list[ForecastPoint]: List of forecast points (3-hour intervals)

        Raises:
            SecurityError: If request fails
        """
        # Validate inputs
        loc_type, city, lat, lon = validate_location(location)
        days = validate_days(days, max_days=5)
        units = validate_units(units)

        # Convert city to coordinates if needed
        if loc_type == "city":
            if city is None:
                msg = "City location validation returned no city name"
                raise SecurityError(msg)
            coords = self.geocode_city(city)
            lat, lon = coords.latitude, coords.longitude
            location_str = city
        else:
            location_str = f"{lat},{lon}"

        # Check rate limit
        rate_limiter.check("forecast")

        # Check cache
        cache_key = f"forecast:{lat},{lon}:{days}:{units}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            audit_log("get_forecast", location_str or "", {"days": days, "cached": True})
            # Type guard for cached value
            if not isinstance(cached, list):
                msg = "Invalid cached forecast data"
                raise SecurityError(msg)
            return cached

        # Make API request
        endpoint = f"{BASE_URL}/forecast"
        params = {"lat": lat, "lon": lon, "units": units, "cnt": days * 8}  # 8 intervals per day

        try:
            data = self._make_request(endpoint, params)

            # Parse response
            forecasts = []
            for item in data["list"]:
                forecast = ForecastPoint(
                    timestamp=item["dt"],
                    datetime_text=item["dt_txt"],
                    temperature=item["main"]["temp"],
                    feels_like=item["main"]["feels_like"],
                    temp_min=item["main"]["temp_min"],
                    temp_max=item["main"]["temp_max"],
                    pressure=item["main"]["pressure"],
                    humidity=item["main"]["humidity"],
                    conditions=[
                        WeatherCondition(
                            id=w["id"],
                            main=w["main"],
                            description=w["description"],
                            icon=w["icon"],
                        )
                        for w in item["weather"]
                    ],
                    clouds=item["clouds"]["all"],
                    wind_speed=item["wind"]["speed"],
                    wind_deg=item["wind"].get("deg"),
                    visibility=item.get("visibility"),
                    pop=item.get("pop", 0.0),
                    rain_3h=item.get("rain", {}).get("3h"),
                    snow_3h=item.get("snow", {}).get("3h"),
                )
                forecasts.append(forecast)

            # Cache result
            self.cache.set(cache_key, forecasts)

            # Audit log
            audit_log(
                "get_forecast",
                location_str or "",
                {
                    "days": days,
                    "points": len(forecasts),
                    "cached": False,
                },
            )

            return forecasts
        except SecurityError:
            raise
        except Exception as e:
            msg = f"Failed to get forecast: {sanitize_error_message(e)}"
            raise SecurityError(msg)

    def get_daily_forecast(
        self, location: str | tuple[float, float], days: int = 5, units: str = "metric"
    ) -> list[DailyForecast]:
        """Get daily aggregated forecast.

        Args:
            location: City name or (latitude, longitude) tuple
            days: Number of days to forecast (1-5)
            units: Temperature units ("metric", "imperial", "standard")

        Returns:
            list[DailyForecast]: Daily forecast summaries

        Raises:
            SecurityError: If request fails
        """
        # Get 3-hour forecasts
        forecasts = self.get_forecast(location, days, units)

        # Aggregate by day
        daily_data: dict[str, list[ForecastPoint]] = {}
        for forecast in forecasts:
            date = forecast.datetime_text.split()[0]
            if date not in daily_data:
                daily_data[date] = []
            daily_data[date].append(forecast)

        # Create daily summaries
        daily_forecasts = []
        for date in sorted(daily_data.keys()):
            points = daily_data[date]

            # Calculate aggregates
            temps = [p.temperature for p in points]
            pops = [p.pop for p in points]
            conditions = [p.conditions[0].main for p in points if p.conditions]
            most_common_condition = (
                max(set(conditions), key=conditions.count) if conditions else "Unknown"
            )

            daily = DailyForecast(
                date=date,
                temp_min=min(temps),
                temp_max=max(temps),
                temp_avg=sum(temps) / len(temps),
                conditions=most_common_condition,
                pop_max=max(pops),
            )
            daily_forecasts.append(daily)

        return daily_forecasts

    def clear_cache(self) -> None:
        """Clear all cached data."""
        self.cache.clear()


# Global client instance (lazy initialization)
_client: WeatherClient | None = None


def get_client() -> WeatherClient:
    """Get or create global WeatherClient instance.

    Returns:
        WeatherClient: Global client instance
    """
    global _client
    if _client is None:
        _client = WeatherClient()
    return _client
