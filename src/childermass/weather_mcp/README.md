# Childermass Weather MCP

OpenWeatherMap integration for the Childermass smart home and personal assistant system. Provides weather data, forecasts, and meteorological alerts through the Model Context Protocol (MCP).

## Features

- **Current Weather**: Real-time weather conditions with temperature, humidity, wind, and more
- **Forecasts**: 5-day forecast with 3-hour intervals, plus daily summaries
- **Smart Queries**: Check rain probability, temperature ranges, activity suitability
- **Location Comparison**: Compare weather across multiple cities
- **Smart Home Integration**: Weather-based automation triggers
- **Activity Planning**: Check if weather is suitable for outdoor activities
- **Astronomical Data**: Sunrise/sunset times for automation and scheduling
- **Geocoding**: Convert city names to coordinates automatically

## Architecture

Following the Childermass MCP patterns established in `gmail_mcp`:

- **Security-First Design**: Input validation, rate limiting, error sanitization
- **Response Caching**: 15-minute TTL to optimize API quota usage
- **Secure Credentials**: Keyring-based storage with file fallback
- **Comprehensive Testing**: 90+ security and functionality tests
- **Audit Logging**: All operations logged for monitoring

## Installation

### Prerequisites

- Python 3.10 or higher
- OpenWeatherMap API key (free tier: 1,000 calls/day)

### Quick Setup

1. **Get an API key** from OpenWeatherMap:
   - Visit: https://openweathermap.org/api
   - Sign up for a free account
   - Generate an API key (32-character hex string)
   - **Note**: New API keys can take up to 2 hours to activate

2. **Run the setup script**:
   ```bash
   cd /Users/ondrej.levy/Agents/Home
   bash src/childermass/weather_mcp/setup.sh
   ```

   The setup script will:
   - Create/use shared virtual environment at `venv/`
   - Install all dependencies
   - Prompt for your OpenWeatherMap API key
   - Store it securely in system keyring
   - Verify the installation

3. **Or manually install**:
   ```bash
   # Create shared virtual environment in project root
   cd /Users/ondrej.levy/Agents/Home
   python3 -m venv venv
   source venv/bin/activate
   
   # Install dependencies
   pip install -r src/childermass/weather_mcp/requirements.txt
   
   # Configure API key
   PYTHONPATH=src python3 -m childermass.weather_mcp.auth --set-api-key YOUR_API_KEY
cd /Users/ondrej.levy/Agents/Home
PYTHONPATH=src python3 -m childermass.weather_mcp.auth --verify

# Run comprehensive test
PYTHONPATH=src venv/bin/python3 src/childermass/weather_mcp/test_setup.py

# Run unit tests
PYTHONPATH=src 
```bash
# Check API key is configured
python -m childermass.weather_mcp.auth --verify

# Run tests
pytest src/childermass/weather_mcp/tests/ -v
```

## ConfigurationUsers/ondrej.levy/Agents/Home/venv/bin/python",
      "args": ["-m", "childermass.weather_mcp.server"],
      "cwd": "/Users/ondrej.levy/Agents/Home/src/childermass/weather_mcp",
      "env": {
        "PYTHONPATH": "/Users/ondrej.levy/Agents/Home/src"
      }
    }
  }
}
```

**Important**: Replace `/Users/ondrej.levy/Agents/Home"],
      "cwd": "/path/to/Agents/Home/src/childermass/weather_mcp",
      "env": {
        "PYTHONPATH": "/path/to/Agents/Home/src"
      }
    }
  }
}
```

**Important**: Replace `/path/to/Agents/Home/src` with your actual workspace path.
PYTHONPATH first (adjust to your workspace)
export PYTHONPATH=/path/to/Agents/Home/src:$PYTHONPATH

# Set 
### API Key Management

```bash
# Set API key
python -m childermass.weather_mcp.auth --set-api-key YOUR_KEY

# Verify API key
python -m childermass.weather_mcp.auth --verify

# Delete API key
python -m childermass.weather_mcp.auth --delete
```

API keys are stored:
1. **Primary**: System keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service)
2. **Fallback**: `~/.childermass/weather_api_key` (chmod 600)

## Available Tools

### Core Weather Tools

#### `weather_get_current(location, units="m", "San Francisco") or coordinates as "lat,lon"
- `units` (str): Temperature units - "metric" (Celsius), "imperial" (Fahrenheit), or "standard" (Kelvin)

**Example:**
```python
weather_get_current("San Francisco", "imperial")
weather_get_current("40.7128,-74.0060", "metriclsius), "imperial" (Fahrenheit), or "standard" (Kelvin)

**Example:**
```python
weather_get_current("San Francisco,US", "imperial")
# Returns: temperature, feels_like, humidity, wind, conditions, etc.
```

#### `weather_get_foreParis", 3, "metric")
weather_get_forecast("51.5074,-0.1278", 5, "imperial")
# Returns: List of forecast points with temperature, precipitation probability
```

#### `weather_get_daily(location, days=5, units="metric")`
Get daily weather forecast summary (one entry per day).

**Example:**
```python
weather_get_daily("Berlintion, days=5, units="metric")`
Get daily weather forecast summary (one entry per day).

**Example:**
```python
weather_get_daily("Berlin,DE", 5, "metric")
# Returns: Daily min/max temperatures, conditions
```

### Specialized Query Tools

#### `weather_check_rain(location, hours=12, units="metric")`
Check if rain is expected in the next N hours.

**Example:**
```python
weather_check_rain("Seattle,US", 6)
# Returns: will_rain, max_probability, total_expected_mm, rain_periods
```

#### `weather_check_temperature_range(location, days=3, units="metric")`
Get temperature range (min/max) for upcoming days.

**Example:**
```python
weather_check_temperature_range("Moscow,RU", 5, "metric")
# Returns: Daily temperature ranges and overall min/max
```

#### `weather_compare_locations(locations, metric="temperature", units="metric")`
Compare current weather across multiple locations.

**Example:**
```python
weather_compare_locations(
    ["London,UK", "Paris,FR", "Berlin,DE"],
    "temperature"
)
# Returns: Comparison data with highest/lowest values
```

### Smart Home / Activity Tools

#### `weather_is_good_for_activity(location, activity, when="now", units="metric")`
Check if weather is suitable for a specific outdoor activity.

**Supported Activities:**
- hiking, running, cycling, picnic, beach, skiing, golf, tennis

**Example:**
```python
weather_is_good_for_activity("Boulder,US", "hiking", "tomorrow")
# Returns: suitable (bool), weather data, reasons
```

#### `weather_search_best_conditions(locations, preferences, units="metric")`
Find location with best weather matching preferences.

**Example:**
```python
weather_search_best_conditions(
    ["Barcelona,ES", "Rome,IT", "Athens,GR"],
    {"temp_min": 22, "temp_max": 28, "no_rain": True}
)
# Returns: Ranked list of locations by preference match
```

### Astronomical & Location Tools

#### `weather_get_sunrise_sunset(location, date="today")`
Get sunrise and sunset times for a location.

**Example:**
```python
weather_get_sunrise_sunset("Sydney,AU", "today")
# Returns: sunrise, sunset, day_length_hours
```

#### `weather_geocode(city_name)`
Convert city name to geographic coordinates.

**Example:**
```python
weather_geocode("Singapore")
# Returns: latitude, longitude, name, country
```

## Use Cases

### Smart Home Automation

```python
# Turn on heating if outdoor temp drops below 10°C tonight
forecast = weather_get_daily("Home Location", 1, "metric")
if forecast["daily_forecast"][0]["temp_min"] < 10:
    # Trigger heating system

# Close blinds if temperature exceeds 30°C
current = weather_get_current("Home Location", "metric")
if current["temperature"] > 30:
    # Close blinds

# Alert if severe weather warning
alerts = weather_check_rain("Home Location", 24)
if alerts["max_probability"] > 80:
    # Send notification
```

### Personal Assistant

```python
# What should I wear today?
weather = weather_get_current("My Location", "metric")
daily = weather_get_daily("My Location", 1, "metric")
# Generate clothing recommendation based on temp and conditions

# Will I need an umbrella?
rain = weather_check_rain("My Location", 12)
if rain["will_rain"]:
    # Remind to take umbrella

# Good weather for hiking this weekend?
suitable = weather_is_good_for_activity("Park Location", "hiking", "tomorrow")
if suitable["suitable"]:
    # Suggest hiking trip
```

### Integration with Other Childermass MCPs

```python
# Calendar: Check weather for event location
event = calendar_get_next_event()
weather = weather_get_current(event["location"], "metric")

# Gmail: Send daily weather forecast
forecast = weather_get_daily("Home", 3, "metric")
gmail_send_email(
    to="user@example.com",
    subject="Daily Weather Forecast",
    body=f"Forecast: {forecast}"
)

# Tasks: Reschedule outdoor tasks if rain
rain = weather_check_rain("Home", 24)
if rain["will_rain"]:
    tasks_reschedule_outdoor_tasks()
```

## Rate Limits

Built-in rate limiting to prevent API quota exhaustion:

- **Current Weather**: 60 requests/minute
- **Forecast**: 30 requests/minute
- **Alerts**: 30 requests/minute
- **Air Quality**: 20 requests/minute
- **Geocoding**: 40 requests/minute
- **Historical**: 10 requests/minute

**Response Caching**: 15-minute TTL reduces effective API calls while keeping data fresh.

## API Quota

OpenWeatherMap Free Tier:
- **1,000 API calls per day** (~42 per hour)
- With caching, supports 150+ effective queries per hour
- Includes: Current weather, 5-day forecast, weather alerts
- Geographic coverage: Worldwide

## Development

### Running Tests
Navigate to project root
cd /Users/ondrej.levy/Agents/Home

# Run all tests
PYTHONPATH=src pytest src/childermass/weather_mcp/tests/ -v

# Run with coverage
PYTHONPATH=src pytest src/childermass/weather_mcp/tests/ --cov=childermass.weather_mcp --cov-report=html

# Run specific test class
PYTHONPATH=src 
# Run specific test class
pytest src/childermass/weather_mcp/tests/test_security.py::TestRateLimiter -v
```

### Project Structure

```
weather_mcp/
├── __init__.py          # Package metadata
├── server.py            # FastMCP server with 11 tools
├── client.py            # OpenWeatherMap API wrapper
├── auth.py              # API key management
├── security.py          # Validation, rate limiting, sanitization
├── requirements.txt     # Dependencies
├── setup.sh             # Installation script
├── README.md            # This file
├── CHANGELOG.md         # Version history
└── tests/
    ├── __init__.py
    └── test_security.py # Comprehensive test suite (90+ tests)
```

### Technology Stack

- **MCP Framework**: `mcp>=1.0.0` (FastMCP)
- **HTTP Client**: `requests>=2.31.0`
- **Credentials**: `keyring>=25.5.0`
- **Validation**: `validators>=0.34.0`
- **Testing**: `pytest>=8.0.0`, `pytest-cov>=4.1.0`

## Troubleshooting

### API Key Issues

```bash
# Verify API key is configured
python -m childermass.weather_mcp.auth --verify

# Check audit log for errors
tail -f ~/.childermass/weather-audit.log
```

### Rate Limit Errors

If you see "Rate limit exceeded" errors:
- Wait for rate limiter to refill (tokens refill per minute)
- Check if caching is working (same queries within 15 min should hit cache)
- Review audit log to identify excessive queries

### Location Not Found

- Use format: "City,CountryCode" (e.g., "London,UK", "Tokyo,JP")
- Or use coordinates: "lat,lon" (e.g., "51.5074,-0.1278")
- Verify city name spelling
- Use `weather_geocode("City,CC")` to test geocoding

### API Quota Exhausted

Free tier: 1,000 calls/day
- Check current usage in OpenWeatherMap dashboard
- Verify caching is enabled (reduces API calls)
- Consider upgrading to paid tier if needed

## Security

- **Input Validation**: All user inputs validated and sanitized
- **Rate Limiting**: Token bucket algorithm prevents abuse
- **Error Sanitization**: API keys and sensitive data removed from errors
- **Audit Logging**: All operations logged to `~/.childermass/weather-audit.log`
- **Secure Storage**: API keys stored in system keyring with file fallback (chmod 600)

## License

Part of the Childermass smart home and personal assistant system.

## Contributing

Follow the Childermass MCP patterns:
1. Validate all inputs with `security.py` validators
2. Apply rate limiting to all client methods
3. Implement response caching where appropriate
4. Sanitize all error messages
5. Add audit logging for all operations
6. Write comprehensive tests (aim for 90%+ coverage)

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review audit logs: `~/.childermass/weather-audit.log`
3. Run tests to verify setup: `pytest -v`
4. Check OpenWeatherMap API status: https://openweathermap.org/api

## Version

Current version: **0.1.0** (Initial Release)

See [CHANGELOG.md](CHANGELOG.md) for version history.
