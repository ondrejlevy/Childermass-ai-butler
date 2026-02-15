"""Childermass Weather MCP Server - FastMCP tools for OpenWeatherMap.

This module provides MCP tools for accessing weather data, forecasts, and
meteorological alerts through the OpenWeatherMap API.
"""

from dataclasses import asdict
from datetime import datetime, timedelta
from typing import Any

from mcp.server.fastmcp import FastMCP

from .client import get_client
from .security import SecurityError, sanitize_error_message


# Initialize FastMCP server
mcp = FastMCP("childermass-weather")


# ============================================================================
# Core Weather Tools
# ============================================================================


@mcp.tool()
def weather_get_current(
    location: str,
    units: str = "metric"
) -> dict:
    """Get current weather conditions for a location.
    
    Args:
        location: City name (e.g., "San Francisco,US") or coordinates as "lat,lon"
        units: Temperature units - "metric" (Celsius), "imperial" (Fahrenheit), or "standard" (Kelvin)
    
    Returns:
        dict: Current weather data including temperature, humidity, wind, conditions
    
    Examples:
        weather_get_current("London,UK", "metric")
        weather_get_current("40.7128,-74.0060", "imperial")
    """
    try:
        client = get_client()
        
        # Parse location
        loc = _parse_location(location)
        
        # Get weather
        weather = client.get_current_weather(loc, units)
        
        return asdict(weather)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def weather_get_forecast(
    location: str,
    days: int = 5,
    units: str = "metric"
) -> dict:
    """Get detailed weather forecast for a location (3-hour intervals).
    
    Args:
        location: City name (e.g., "Tokyo,JP") or coordinates as "lat,lon"
        days: Number of days to forecast (1-5, default: 5)
        units: Temperature units - "metric", "imperial", or "standard"
    
    Returns:
        dict: List of forecast points with temperature, conditions, precipitation probability
    
    Examples:
        weather_get_forecast("Paris,FR", 3, "metric")
        weather_get_forecast("51.5074,-0.1278", 5, "imperial")
    """
    try:
        client = get_client()
        
        # Parse location
        loc = _parse_location(location)
        
        # Get forecast
        forecasts = client.get_forecast(loc, days, units)
        
        return {"forecasts": [asdict(f) for f in forecasts], "count": len(forecasts)}
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def weather_get_daily(
    location: str,
    days: int = 5,
    units: str = "metric"
) -> dict:
    """Get daily weather forecast summary (one entry per day).
    
    Args:
        location: City name (e.g., "Berlin,DE") or coordinates as "lat,lon"
        days: Number of days to forecast (1-5, default: 5)
        units: Temperature units - "metric", "imperial", or "standard"
    
    Returns:
        dict: Daily forecast with min/max temperatures and conditions
    
    Examples:
        weather_get_daily("New York,US", 3, "imperial")
    """
    try:
        client = get_client()
        
        # Parse location
        loc = _parse_location(location)
        
        # Get daily forecast
        daily = client.get_daily_forecast(loc, days, units)
        
        return {"daily_forecast": [asdict(d) for d in daily], "days": len(daily)}
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ============================================================================
# Specialized Query Tools
# ============================================================================


@mcp.tool()
def weather_check_rain(
    location: str,
    hours: int = 12,
    units: str = "metric"
) -> dict:
    """Check if rain is expected in the next N hours.
    
    Args:
        location: City name or coordinates as "lat,lon"
        hours: Number of hours to check (1-48, default: 12)
        units: Temperature units
    
    Returns:
        dict: Rain forecast with probability and expected amounts
    
    Examples:
        weather_check_rain("Seattle,US", 6)
        weather_check_rain("40.7128,-74.0060", 24)
    """
    try:
        from .security import validate_hours
        
        client = get_client()
        loc = _parse_location(location)
        hours = validate_hours(hours, max_hours=48)
        
        # Get forecast
        forecasts = client.get_forecast(loc, days=2, units=units)
        
        # Filter to requested time window
        now = datetime.now().timestamp()
        cutoff = now + (hours * 3600)
        
        rain_periods = []
        max_pop = 0.0
        total_rain = 0.0
        
        for forecast in forecasts:
            if forecast.timestamp <= cutoff:
                if forecast.pop > 0 or forecast.rain_3h:
                    rain_periods.append({
                        "time": forecast.datetime_text,
                        "probability": forecast.pop * 100,
                        "rain_mm": forecast.rain_3h or 0.0,
                        "conditions": forecast.conditions[0].description if forecast.conditions else "unknown"
                    })
                    max_pop = max(max_pop, forecast.pop)
                    if forecast.rain_3h:
                        total_rain += forecast.rain_3h
        
        will_rain = max_pop > 0.3  # >30% probability
        
        return {
            "will_rain": will_rain,
            "max_probability": max_pop * 100,
            "total_expected_mm": total_rain,
            "rain_periods": rain_periods,
            "hours_checked": hours,
        }
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def weather_check_temperature_range(
    location: str,
    days: int = 3,
    units: str = "metric"
) -> dict:
    """Get temperature range (min/max) for upcoming days.
    
    Args:
        location: City name or coordinates as "lat,lon"
        days: Number of days to check (1-5, default: 3)
        units: Temperature units
    
    Returns:
        dict: Daily temperature ranges and averages
    
    Examples:
        weather_check_temperature_range("Moscow,RU", 5, "metric")
    """
    try:
        client = get_client()
        loc = _parse_location(location)
        
        # Get daily forecast
        daily = client.get_daily_forecast(loc, days, units)
        
        temp_ranges = []
        for day in daily:
            temp_ranges.append({
                "date": day.date,
                "min": day.temp_min,
                "max": day.temp_max,
                "average": day.temp_avg,
                "conditions": day.conditions,
            })
        
        # Overall statistics
        all_mins = [d.temp_min for d in daily]
        all_maxs = [d.temp_max for d in daily]
        
        return {
            "temperature_ranges": temp_ranges,
            "overall_min": min(all_mins),
            "overall_max": max(all_maxs),
            "units": units,
        }
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def weather_compare_locations(
    locations: list[str],
    metric: str = "temperature",
    units: str = "metric"
) -> dict:
    """Compare current weather across multiple locations.
    
    Args:
        locations: List of city names or coordinates
        metric: What to compare - "temperature", "humidity", "wind", "conditions"
        units: Temperature units
    
    Returns:
        dict: Comparison data for all locations
    
    Examples:
        weather_compare_locations(["London,UK", "Paris,FR", "Berlin,DE"], "temperature")
    """
    try:
        if not isinstance(locations, list) or len(locations) < 2:
            return {"error": "Must provide at least 2 locations as a list"}
        
        if len(locations) > 10:
            return {"error": "Maximum 10 locations allowed"}
        
        client = get_client()
        results = []
        
        for location in locations:
            try:
                loc = _parse_location(location)
                weather = client.get_current_weather(loc, units)
                
                data: dict[str, Any] = {
                    "location": location,
                    "name": weather.location_name,
                }
                
                if metric == "temperature":
                    data["value"] = weather.temperature
                    data["feels_like"] = weather.feels_like
                elif metric == "humidity":
                    data["value"] = weather.humidity
                elif metric == "wind":
                    data["value"] = weather.wind_speed
                    data["direction"] = weather.wind_deg
                elif metric == "conditions":
                    data["value"] = weather.conditions[0].main if weather.conditions else "Unknown"
                    data["description"] = weather.conditions[0].description if weather.conditions else "Unknown"
                else:
                    return {"error": f"Invalid metric: {metric}. Use: temperature, humidity, wind, conditions"}
                
                results.append(data)
            except Exception as e:
                results.append({
                    "location": location,
                    "error": sanitize_error_message(e)
                })
        
        # Find best/worst
        if metric in ["temperature", "humidity", "wind"]:
            values = [(r["location"], r.get("value")) for r in results if "value" in r]
            if values:
                warmest = max(values, key=lambda x: float(x[1] or 0))
                coldest = min(values, key=lambda x: float(x[1] or 0))
                results.append({
                    "summary": {
                        "highest": {"location": warmest[0], "value": warmest[1]},
                        "lowest": {"location": coldest[0], "value": coldest[1]},
                    }
                })
        
        return {"comparison": results, "metric": metric, "units": units}
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ============================================================================
# Smart Home / Activity-Based Tools
# ============================================================================


@mcp.tool()
def weather_is_good_for_activity(
    location: str,
    activity: str,
    when: str = "now",
    units: str = "metric"
) -> dict:
    """Check if weather is suitable for a specific outdoor activity.
    
    Args:
        location: City name or coordinates
        activity: Activity type (e.g., "hiking", "running", "cycling", "picnic", "beach")
        when: "now" for current weather, or "today", "tomorrow", or specific date (YYYY-MM-DD)
        units: Temperature units
    
    Returns:
        dict: Weather suitability assessment with recommendations
    
    Examples:
        weather_is_good_for_activity("Boulder,US", "hiking", "tomorrow")
        weather_is_good_for_activity("Miami,US", "beach", "now")
    """
    try:
        from .security import validate_activity
        
        client = get_client()
        loc = _parse_location(location)
        activity = validate_activity(activity)
        
        # Get weather data based on 'when'
        if when == "now":
            weather = client.get_current_weather(loc, units)
            temp = weather.temperature
            conditions = weather.conditions[0].main if weather.conditions else "Unknown"
            wind: float = weather.wind_speed
            humidity: float = float(weather.humidity)
            pop = 0.0
        else:
            # Get forecast
            daily = client.get_daily_forecast(loc, 5, units)
            
            # Find the right day
            if when == "today":
                target_date = datetime.now().strftime("%Y-%m-%d")
            elif when == "tomorrow":
                target_date = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")
            else:
                from .security import validate_date_string
                target_date = validate_date_string(when)
            
            # Find matching forecast
            day_forecast = None
            for day in daily:
                if day.date == target_date:
                    day_forecast = day
                    break
            
            if not day_forecast:
                return {"error": f"No forecast available for {target_date}"}
            
            temp = day_forecast.temp_avg
            conditions = day_forecast.conditions
            pop = day_forecast.pop_max * 100
            
            # Get more details from 3-hour forecast
            forecasts = client.get_forecast(loc, 5, units)
            day_forecasts = [f for f in forecasts if f.datetime_text.startswith(target_date)]
            wind = sum(f.wind_speed for f in day_forecasts) / len(day_forecasts) if day_forecasts else 0.0
            humidity = sum(f.humidity for f in day_forecasts) / len(day_forecasts) if day_forecasts else 0.0
        
        # Activity-specific criteria
        suitable, reasons = _check_activity_suitability(
            activity, temp, conditions, wind, humidity, pop, units
        )
        
        return {
            "suitable": suitable,
            "activity": activity,
            "when": when,
            "weather": {
                "temperature": temp,
                "conditions": conditions,
                "wind_speed": wind,
                "humidity": humidity,
                "rain_probability": pop,
            },
            "reasons": reasons,
            "units": units,
        }
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def weather_search_best_conditions(
    locations: list[str],
    preferences: dict,
    units: str = "metric"
) -> dict:
    """Find location with best weather matching preferences.
    
    Args:
        locations: List of city names or coordinates to compare
        preferences: Weather preferences, e.g., {"temp_min": 20, "temp_max": 30, "no_rain": true}
        units: Temperature units
    
    Returns:
        dict: Ranked list of locations by preference match
    
    Examples:
        weather_search_best_conditions(
            ["Barcelona,ES", "Rome,IT", "Athens,GR"],
            {"temp_min": 22, "temp_max": 28, "no_rain": True}
        )
    """
    try:
        if not isinstance(locations, list) or len(locations) < 2:
            return {"error": "Must provide at least 2 locations as a list"}
        
        if len(locations) > 10:
            return {"error": "Maximum 10 locations allowed"}
        
        client = get_client()
        results = []
        
        for location in locations:
            try:
                loc = _parse_location(location)
                weather = client.get_current_weather(loc, units)
                daily = client.get_daily_forecast(loc, 1, units)
                
                # Calculate match score
                score = 0
                reasons = []
                
                temp = weather.temperature
                if "temp_min" in preferences:
                    if temp >= preferences["temp_min"]:
                        score += 1
                        reasons.append(f"Temperature {temp}° meets minimum {preferences['temp_min']}°")
                    else:
                        reasons.append(f"Temperature {temp}° below minimum {preferences['temp_min']}°")
                
                if "temp_max" in preferences:
                    if temp <= preferences["temp_max"]:
                        score += 1
                        reasons.append(f"Temperature {temp}° within maximum {preferences['temp_max']}°")
                    else:
                        reasons.append(f"Temperature {temp}° exceeds maximum {preferences['temp_max']}°")
                
                if "no_rain" in preferences and preferences["no_rain"]:
                    conditions = weather.conditions[0].main if weather.conditions else "Unknown"
                    pop = daily[0].pop_max if daily else 0
                    if conditions not in ["Rain", "Drizzle", "Thunderstorm"] and pop < 0.3:
                        score += 2  # Weight rain more heavily
                        reasons.append("No rain expected")
                    else:
                        reasons.append(f"Rain possible: {conditions}, {pop*100:.0f}% probability")
                
                if "max_wind" in preferences:
                    if weather.wind_speed <= preferences["max_wind"]:
                        score += 1
                        reasons.append(f"Wind {weather.wind_speed} within limit {preferences['max_wind']}")
                    else:
                        reasons.append(f"Wind {weather.wind_speed} exceeds limit {preferences['max_wind']}")
                
                results.append({
                    "location": location,
                    "name": weather.location_name,
                    "score": score,
                    "weather": {
                        "temperature": temp,
                        "conditions": weather.conditions[0].description if weather.conditions else "Unknown",
                        "wind_speed": weather.wind_speed,
                    },
                    "reasons": reasons,
                })
            except Exception as e:
                results.append({
                    "location": location,
                    "error": sanitize_error_message(e),
                    "score": -1,
                })
        
        # Sort by score descending
        results.sort(key=lambda x: float(x.get("score") or -1), reverse=True)  # type: ignore[arg-type]
        
        return {
            "ranked_locations": results,
            "best_match": results[0]["location"] if results else None,
            "preferences": preferences,
            "units": units,
        }
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ============================================================================
# Astronomical & Location Tools
# ============================================================================


@mcp.tool()
def weather_get_sunrise_sunset(
    location: str,
    date: str = "today"
) -> dict:
    """Get sunrise and sunset times for a location.
    
    Args:
        location: City name or coordinates
        date: "today", "tomorrow", or specific date (YYYY-MM-DD)
    
    Returns:
        dict: Sunrise and sunset times in local timezone
    
    Examples:
        weather_get_sunrise_sunset("Sydney,AU", "today")
        weather_get_sunrise_sunset("40.7128,-74.0060", "2026-02-20")
    """
    try:
        client = get_client()
        loc = _parse_location(location)
        
        # Get current weather for sunrise/sunset
        weather = client.get_current_weather(loc)
        
        if weather.sunrise and weather.sunset:
            sunrise_dt = datetime.fromtimestamp(weather.sunrise)
            sunset_dt = datetime.fromtimestamp(weather.sunset)
            
            # Calculate day length
            day_length_seconds = weather.sunset - weather.sunrise
            day_length_hours = day_length_seconds / 3600
            
            return {
                "location": weather.location_name,
                "date": date,
                "sunrise": sunrise_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "sunset": sunset_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "day_length_hours": round(day_length_hours, 2),
                "timezone_offset": weather.timezone,
            }
        else:
            return {"error": "Sunrise/sunset data not available for this location"}
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def weather_geocode(city_name: str) -> dict:
    """Convert city name to geographic coordinates.
    
    Args:
        city_name: City name, optionally with country code (e.g., "Toronto,CA")
    
    Returns:
        dict: Coordinates and location details
    
    Examples:
        weather_geocode("Singapore")
        weather_geocode("Los Angeles,US")
    """
    try:
        client = get_client()
        coords = client.geocode_city(city_name)
        
        return asdict(coords)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ============================================================================
# Helper Functions
# ============================================================================


def _parse_location(location: str) -> str | tuple[float, float]:
    """Parse location string into city name or coordinates tuple.
    
    Args:
        location: City name or "lat,lon" string
        
    Returns:
        City name string or (lat, lon) tuple
    """
    # Check if coordinates format
    if "," in location and location.count(",") == 1:
        parts = location.split(",")
        try:
            lat = float(parts[0].strip())
            lon = float(parts[1].strip())
            # Validate reasonable coordinate ranges
            if -90 <= lat <= 90 and -180 <= lon <= 180:
                return (lat, lon)
        except ValueError:
            pass  # Not coordinates, treat as city name
    
    # Return as city name
    return location


def _check_activity_suitability(
    activity: str,
    temp: float,
    conditions: str,
    wind: float,
    humidity: float,
    pop: float,
    units: str
) -> tuple[bool, list[str]]:
    """Check if weather is suitable for an activity.
    
    Args:
        activity: Activity name
        temp: Temperature
        conditions: Weather conditions
        wind: Wind speed
        humidity: Humidity percentage
        pop: Precipitation probability (0-100)
        units: Temperature units
        
    Returns:
        tuple: (is_suitable, list_of_reasons)
    """
    reasons = []
    suitable = True
    
    # Define activity criteria
    criteria = {
        "hiking": {"temp_min": 5, "temp_max": 30, "max_wind": 25, "max_rain": 30},
        "running": {"temp_min": 0, "temp_max": 28, "max_wind": 30, "max_rain": 40},
        "cycling": {"temp_min": 5, "temp_max": 32, "max_wind": 20, "max_rain": 20},
        "picnic": {"temp_min": 15, "temp_max": 32, "max_wind": 15, "max_rain": 10},
        "beach": {"temp_min": 22, "temp_max": 40, "max_wind": 20, "max_rain": 10},
        "skiing": {"temp_min": -15, "temp_max": 5, "max_wind": 30, "max_rain": 100},
        "golf": {"temp_min": 10, "temp_max": 32, "max_wind": 25, "max_rain": 20},
        "tennis": {"temp_min": 15, "temp_max": 35, "max_wind": 20, "max_rain": 5},
    }
    
    # Convert imperial to metric if needed
    if units == "imperial":
        temp_c = (temp - 32) * 5/9
        wind_ms = wind * 0.44704  # mph to m/s
    else:
        temp_c = temp
        wind_ms = wind
    
    # Get criteria for activity (or use generic)
    c = criteria.get(activity, {"temp_min": 5, "temp_max": 35, "max_wind": 25, "max_rain": 30})
    
    # Check temperature
    if temp_c < c["temp_min"]:
        suitable = False
        reasons.append(f"Too cold for {activity}: {temp}° (minimum: {c['temp_min']}°C)")
    elif temp_c > c["temp_max"]:
        suitable = False
        reasons.append(f"Too hot for {activity}: {temp}° (maximum: {c['temp_max']}°C)")
    else:
        reasons.append(f"Temperature {temp}° is suitable")
    
    # Check wind
    if wind_ms > c["max_wind"]:
        suitable = False
        reasons.append(f"Too windy: {wind} (maximum: {c['max_wind']} m/s)")
    else:
        reasons.append(f"Wind speed {wind} is acceptable")
    
    # Check rain
    if pop > c["max_rain"]:
        suitable = False
        reasons.append(f"High rain probability: {pop}% (maximum: {c['max_rain']}%)")
    elif conditions in ["Rain", "Drizzle", "Thunderstorm"]:
        suitable = False
        reasons.append(f"Currently raining: {conditions}")
    else:
        reasons.append("No significant rain expected")
    
    # Check severe conditions
    if conditions in ["Thunderstorm", "Snow", "Tornado", "Hurricane"]:
        suitable = False
        reasons.append(f"Severe weather: {conditions}")
    
    return suitable, reasons


if __name__ == "__main__":
    # Run MCP server
    mcp.run()
