"""Childermass Weather MCP - OpenWeatherMap integration for smart home and personal assistant."""

__version__ = "0.1.0"
__author__ = "Childermass Team"
__description__ = "MCP server for weather data, forecasts, and meteorological alerts"

from .server import mcp
from .client import WeatherClient

__all__ = ["mcp", "WeatherClient", "__version__"]
