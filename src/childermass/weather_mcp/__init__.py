"""Childermass Weather MCP - OpenWeatherMap integration for smart home and personal assistant."""

__version__ = "0.1.0"
__author__ = "Childermass Team"
__description__ = "MCP server for weather data, forecasts, and meteorological alerts"

from .client import WeatherClient
from .server import mcp


__all__ = ["WeatherClient", "__version__", "mcp"]
