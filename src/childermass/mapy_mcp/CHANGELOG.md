# Changelog

All notable changes to the Childermass Mapy.com MCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-14

### Added

#### Geocoding & Places Tools
- `mapy_search_places()` - Search for places, addresses, POIs by text query
- `mapy_suggest_places()` - Autocomplete places with typo tolerance
- `mapy_reverse_geocode()` - Get address information from coordinates

#### Route Planning & Navigation Tools
- `mapy_plan_route()` - Plan route with waypoints, toll/highway avoidance, departure time
- `mapy_travel_time()` - Get simplified travel time and distance
- `mapy_compare_routes()` - Compare multiple transport modes for same route
- `mapy_find_nearest()` - Find nearest destination using matrix routing

#### Elevation & Timezone Tools
- `mapy_get_elevation()` - Get elevation in meters for up to 256 positions
- `mapy_get_timezone()` - Get timezone, local time, UTC offset by coordinates or IANA name

#### Security Features
- Input validation for all parameters (queries, coordinates, route types, etc.)
- Rate limiting with token bucket algorithm (per-operation limits)
- Error sanitization to prevent API key leakage
- Audit logging to `~/.childermass/mapy-audit.log`
- Secure API key storage in system keyring with file fallback

#### Client Features
- Mapy.com REST API integration (geocoding, routing, elevation, timezone)
- Response caching with 15-minute TTL
- API key authentication via `X-Mapy-Api-Key` header
- Support for 7 route types (car, foot, bike variants)
- Comprehensive error handling with user-friendly messages

#### Development & Testing
- Comprehensive security tests (70+ test cases)
- Pytest integration with coverage reporting
- Automated setup script (`setup.sh`)
- CLI for API key management
