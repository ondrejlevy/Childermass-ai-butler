# Changelog

All notable changes to the Childermass Places MCP Server.

## [1.0.0] - 2025-02-14

### Added
- Initial release of Places MCP server
- **Text Search** tool (`places_text_search`) – search places by natural language query with location bias, type filter, rating filter, price filter, open-now filter
- **Nearby Search** tool (`places_nearby_search`) – find places near geographic coordinates with type inclusion/exclusion
- **Search with Filters** tool (`places_search_with_filters`) – convenience wrapper with advanced filtering
- **Place Details** tool (`places_get_details`) – full place information including address, phone, website, hours, reviews, photos, attributes, accessibility
- **Opening Hours** tool (`places_get_opening_hours`) – focused opening hours retrieval
- **Reviews** tool (`places_get_reviews`) – user reviews with ratings
- **Autocomplete** tool (`places_autocomplete`) – interactive place suggestions
- **Photo** tool (`places_get_photo`) – retrieve photo URIs from resource names
- **Find Nearby Service** tool (`places_find_nearby_service`) – smart home assistant: plumbers, electricians, etc.
- **Find Restaurants** tool (`places_find_restaurants`) – restaurant search with cuisine and price filters
- **Find EV Chargers** tool (`places_find_ev_chargers`) – EV charging station search with connector type filter
- OAuth 2.0 authentication with secure keyring token storage
- Multi-account support
- Input validation on all parameters (place IDs, coordinates, types, queries, etc.)
- Token bucket rate limiting (per-account, per-operation)
- JSON audit logging to `~/.childermass/places-audit.log`
- Error message sanitization (API keys, tokens, paths never leaked)
- Comprehensive security test suite (~85 tests)
- Setup script for one-command installation
