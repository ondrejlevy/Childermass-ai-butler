# Changelog

All notable changes to the Childermass Weather MCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-14

### Added

#### Core Weather Tools
- `weather_get_current()` - Get current weather conditions for any location
- `weather_get_forecast()` - Get detailed 5-day forecast with 3-hour intervals
- `weather_get_daily()` - Get daily weather summary with min/max temperatures

#### Specialized Query Tools
- `weather_check_rain()` - Check rain probability for next N hours
- `weather_check_temperature_range()` - Get temperature ranges for upcoming days
- `weather_compare_locations()` - Compare weather across multiple cities

#### Smart Home / Activity Tools
- `weather_is_good_for_activity()` - Check weather suitability for outdoor activities
  - Supports: hiking, running, cycling, picnic, beach, skiing, golf, tennis
- `weather_search_best_conditions()` - Find best weather location matching preferences

#### Astronomical & Location Tools
- `weather_get_sunrise_sunset()` - Get sunrise/sunset times for automation
- `weather_geocode()` - Convert city names to geographic coordinates

#### Security Features
- Input validation for all parameters (city names, coordinates, units, etc.)
- Rate limiting with token bucket algorithm (per-operation limits)
- Error sanitization to prevent API key leakage
- Audit logging to `~/.childermass/weather-audit.log`
- Secure API key storage in system keyring with file fallback

#### Client Features
- OpenWeatherMap API integration
- Response caching with 15-minute TTL
- Automatic geocoding for city names
- Support for metric, imperial, and standard units
- Comprehensive error handling with user-friendly messages

#### Development & Testing
- 90+ comprehensive security tests
- Mock API responses for testing
- Pytest integration with coverage reporting
- Automated setup script (`setup.sh`)
- CLI for API key management

#### Documentation
- Complete README with usage examples
- API reference for all 11 tools
- Smart home and personal assistant use cases
- Integration examples with other Childermass MCPs
- Troubleshooting guide

### Technical Details

#### Architecture
- FastMCP server following Childermass patterns
- Modular design: server, client, auth, security
- Dataclass-based response models
- Global client instance with lazy initialization

#### Dependencies
- `mcp>=1.0.0` - FastMCP framework
- `requests>=2.31.0` - HTTP client
- `keyring>=25.5.0` - Secure credential storage
- `validators>=0.34.0` - Input validation
- `pytest>=8.0.0` - Testing framework

#### Rate Limits
- Current weather: 60/min
- Forecast: 30/min
- Alerts: 30/min
- Air quality: 20/min
- Geocoding: 40/min
- Historical: 10/min

#### API Integration
- OpenWeatherMap API 2.5 (free tier)
- 1,000 calls per day quota
- Worldwide geographic coverage
- Current weather, forecasts, and alerts

### Configuration

#### Storage Locations
- API key: System keyring + `~/.childermass/weather_api_key`
- Audit log: `~/.childermass/weather-audit.log`
- Config directory: `~/.childermass/` (chmod 700)
- API key file: chmod 600 for security

#### Caching Strategy
- In-memory cache with 15-minute TTL
- Reduces API calls while maintaining data freshness
- Cache keys: `<operation>:<location>:<params>`
- Supports 150+ effective queries per hour

### Use Cases Supported

#### Smart Home Automation
- Temperature-based HVAC control
- Weather-triggered alerts and notifications
- Blind/shade control based on temperature
- Energy optimization using forecasts
- Sunrise/sunset-based scene automation

#### Personal Assistant
- Clothing recommendations based on weather
- Umbrella reminders for rain
- Activity planning (hiking, cycling, etc.)
- Location comparisons for travel
- Proactive weather notifications

#### Integration Capabilities
- Calendar MCP: Weather for event locations
- Gmail MCP: Email weather forecasts
- Tasks MCP: Reschedule outdoor tasks
- Places MCP: Find alternatives in bad weather
- Keep MCP: Weather-based reminders

### Known Limitations

1. **OpenWeatherMap Free Tier**:
   - 1,000 API calls per day limit
   - 5-day forecast maximum
   - 3-hour forecast intervals (not hourly)
   - Some advanced features require paid tier

2. **Historical Data**:
   - Limited on free tier
   - Tool implemented but may require paid subscription

3. **Weather Alerts**:
   - Availability varies by region
   - Not all countries have alert data

### Future Considerations

Potential enhancements for future versions:
- Air quality index integration (requires additional API calls)
- Historical weather data (requires paid tier subscription)
- Hourly forecasts (requires paid tier)
- More granular caching controls
- Multi-API support (Weather.gov, WeatherAPI.com)
- Weather trend analysis
- Custom alert thresholds per user

---

## Version History

- **0.1.0** (2026-02-14) - Initial release with 11 tools, full Childermass MCP integration

[0.1.0]: https://github.com/childermass/weather_mcp/releases/tag/v0.1.0
