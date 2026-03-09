"""
UniFi Network API Client Wrapper

Provides a clean interface for UniFi Network API operations with integrated security.
All communication is local – direct HTTPS to the console on the LAN.

Security features:
- Input validation on all public functions
- Rate limiting per operation type
- Audit logging for state-changing operations
- Error message sanitization to prevent credential leaks
- Session auto-refresh on 401

API reference: https://developer.ui.com/network/v10.1.84/
"""

import logging
import time
from dataclasses import dataclass

import httpx
import urllib3

from .auth import get_console_url, get_credentials, get_site_id, load_config, verify_ssl
from .security import (
    SecurityError,
    audit_log,
    rate_limiter,
    validate_dpi_type,
    validate_event_limit,
    validate_filter_expression,
    validate_history_hours,
    validate_mac_address,
    validate_max_results,
    validate_network_id,
    validate_network_name,
    validate_offset,
    validate_period,
    validate_policy_action,
    validate_policy_id,
    validate_policy_name,
    validate_site_id,
    validate_timestamp_ms,
    validate_vlan_id,
    validate_voucher_id,
    validate_voucher_params,
    validate_zone_id,
)


# Suppress InsecureRequestWarning for self-signed console certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# API path prefix for Network integration API
_API_PREFIX = "/proxy/network/integration/v1"

# Classic stat/REST API prefix (requires site name, usually "default")
_CLASSIC_PREFIX = "/proxy/network/api/s"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


@dataclass
class NetworkInfo:
    """Application version info."""

    version: str


@dataclass
class Network:
    """Network configuration."""

    id: str
    name: str
    enabled: bool
    vlan_id: int | None
    is_default: bool
    management: str | None  # network management type
    dhcp_guarding_enabled: bool
    trusted_dhcp_servers: list[str]


@dataclass
class NetworkReference:
    """References to a network (clients, devices using it)."""

    network_id: str
    network_name: str
    references: list[dict]


@dataclass
class FirewallPolicy:
    """Firewall policy rule."""

    id: str
    name: str
    enabled: bool
    description: str
    index: int
    action: str  # ALLOW, DROP, REJECT
    source_zone_id: str
    destination_zone_id: str
    ip_version: str
    logging_enabled: bool
    schedule_mode: str
    connection_states: list[str]
    ipsec_filter: str | None


@dataclass
class FirewallZone:
    """Firewall zone."""

    id: str
    name: str


@dataclass
class Voucher:
    """Hotspot voucher."""

    id: str
    name: str | None
    code: str
    created_at: str | None
    activated_at: str | None
    expires_at: str | None
    expired: bool
    time_limit_minutes: int | None
    data_limit_mb: int | None
    download_limit_kbps: int | None
    upload_limit_kbps: int | None
    guest_limit: int | None
    guest_count: int


@dataclass
class PolicyOrdering:
    """Firewall policy ordering."""

    policy_ids: list[str]


# ---------------------------------------------------------------------------
# Classic API Data Classes
# ---------------------------------------------------------------------------


@dataclass
class HealthStatus:
    """Overall site health summary from classic API."""

    status: str  # ok, warning, error
    num_ap: int
    num_adopted: int
    num_disconnected: int
    num_pending: int
    num_gw: int
    num_sw: int
    wan_ip: str
    lan_ip: str
    isp_name: str
    uptime_seconds: int
    latency_ms: int
    download_speed_mbps: float
    upload_speed_mbps: float
    mem_used_pct: float
    cpu_used_pct: float
    subsystems: dict


@dataclass
class ActiveClient:
    """A client currently connected to the network."""

    mac: str
    hostname: str
    ip: str
    network: str  # network name
    is_wired: bool
    rx_bytes: int
    tx_bytes: int
    uptime_seconds: int
    last_seen: int  # epoch seconds
    signal: int | None  # dBm, None for wired
    satisfaction: int | None  # 0-100 experience score
    oui: str  # manufacturer OUI
    blocked: bool
    noted: bool
    name: str | None  # user-given alias


@dataclass
class DeviceInfo:
    """A UniFi network device (AP, switch, gateway)."""

    mac: str
    model: str
    name: str
    type: str  # uap, usw, ugw
    adopted: bool
    state: int  # 1=connected, …
    ip: str
    version: str  # firmware version
    uptime_seconds: int
    last_seen: int
    satisfaction: int | None
    num_clients: int
    cpu_used_pct: float
    mem_used_pct: float


@dataclass
class SiteStats:
    """Aggregated site traffic statistics for a time bucket."""

    time_epoch: int  # bucket start (ms)
    wan_rx_bytes: int
    wan_tx_bytes: int
    num_sta: int  # number of clients
    lan_num_sta: int
    wlan_num_sta: int


@dataclass
class DpiStat:
    """Deep Packet Inspection traffic entry."""

    cat: int  # application category ID
    app: int  # application ID
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int


@dataclass
class IpsEvent:
    """Intrusion Prevention System alert."""

    timestamp: int  # epoch ms
    key: str  # unique alert key
    msg: str  # human message
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    proto: str
    catname: str  # IPS category name
    action: str  # alert / drop
    in_iface: str  # interface
    archived: bool


@dataclass
class RogueAp:
    """Rogue / neighbouring access point."""

    bssid: str  # MAC of rogue AP
    essid: str  # SSID name
    channel: int
    rssi: int  # signal strength
    security: str
    oui: str  # manufacturer
    band: str  # 2.4GHz / 5GHz / 6GHz
    age_seconds: int
    last_seen: int  # epoch seconds
    ap_mac: str  # our AP that detected it
    is_rogue: bool  # true = rogue, false = neighbour


@dataclass
class Alarm:
    """System alarm / alert from the controller."""

    id: str
    key: str
    msg: str
    datetime: str  # ISO timestamp
    archived: bool
    handled: bool


@dataclass
class RfChannel:
    """RF environment channel utilisation (from RF scan or stats)."""

    channel: int
    band: str
    utilization_pct: float
    interference_pct: float
    num_bss: int  # number of BSSIDs seen on channel


@dataclass
class Event:
    """Controller event log entry."""

    id: str
    key: str
    msg: str
    datetime: str  # ISO timestamp
    subsystem: str  # wlan, lan, www, …


# ---------------------------------------------------------------------------
# Session Management
# ---------------------------------------------------------------------------


class _NetworkSession:
    """
    Manages authenticated HTTP session to the console.

    Handles login, CSRF tokens, cookies, and auto-refresh.
    """

    def __init__(self) -> None:
        self._client: httpx.Client | None = None
        self._csrf_token: str = ""
        self._base_url: str = ""
        self._last_login: float = 0

    def _ensure_client(self) -> httpx.Client:
        """Get or create the HTTP client."""
        if self._client is None:
            config = load_config()
            if config is None:
                msg = (
                    "Console not configured. Run setup first:\n"
                    "  python -m childermass.network_mcp.auth --setup"
                )
                raise RuntimeError(msg)

            self._base_url = get_console_url(config)
            ssl = verify_ssl(config)

            self._client = httpx.Client(
                verify=ssl,
                timeout=30.0,
                follow_redirects=True,
            )

        return self._client

    def _login(self) -> None:
        """Authenticate with the console and store session."""
        client = self._ensure_client()
        config = load_config()
        username, password = get_credentials(config)

        # Step 1: Get initial CSRF token
        try:
            resp = client.get(self._base_url)
            self._csrf_token = resp.headers.get("x-csrf-token", "")
        except httpx.ConnectError:
            msg = "Cannot connect to console. Check that it is reachable."
            raise RuntimeError(msg)

        # Step 2: Login
        login_resp = client.post(
            f"{self._base_url}/api/auth/login",
            json={
                "username": username,
                "password": password,
                "rememberMe": True,
                "token": "",
            },
            headers={"x-csrf-token": self._csrf_token},
        )

        if login_resp.status_code == 401:
            msg = "Console authentication failed – invalid username or password"
            raise SecurityError(msg)
        if login_resp.status_code != 200:
            msg = f"Console login failed with HTTP {login_resp.status_code}"
            raise RuntimeError(msg)

        # Step 3: Extract updated CSRF token
        self._csrf_token = login_resp.headers.get(
            "x-updated-csrf-token",
            login_resp.headers.get("x-csrf-token", self._csrf_token),
        )
        self._last_login = time.monotonic()

        logger.info("Authenticated with console at %s", self._base_url)

    def _ensure_authenticated(self) -> None:
        """Ensure we have an active session, login if needed."""
        if self._last_login == 0:
            self._login()

    def request(
        self,
        method: str,
        path: str,
        **kwargs,
    ) -> httpx.Response:
        """
        Make an authenticated request to the Network API.

        Auto-retries once on 401 (session expired).
        """
        self._ensure_authenticated()
        client = self._ensure_client()

        url = f"{self._base_url}{path}"
        headers = kwargs.pop("headers", {})
        headers["x-csrf-token"] = self._csrf_token

        resp = client.request(method, url, headers=headers, **kwargs)

        # Auto re-login on 401
        if resp.status_code == 401:
            logger.info("Session expired, re-authenticating...")
            self._login()
            headers["x-csrf-token"] = self._csrf_token
            resp = client.request(method, url, headers=headers, **kwargs)

        return resp

    def get(self, path: str, **kwargs) -> httpx.Response:
        """GET request."""
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs) -> httpx.Response:
        """POST request."""
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs) -> httpx.Response:
        """PUT request."""
        return self.request("PUT", path, **kwargs)

    def patch(self, path: str, **kwargs) -> httpx.Response:
        """PATCH request."""
        return self.request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs) -> httpx.Response:
        """DELETE request."""
        return self.request("DELETE", path, **kwargs)

    def get_json(self, path: str, **kwargs) -> dict | list:
        """GET request that returns parsed JSON."""
        resp = self.get(path, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def close(self) -> None:
        """Close the HTTP session."""
        if self._client:
            self._client.close()
            self._client = None
            self._last_login = 0


# Module-level session singleton
_session = _NetworkSession()


# ---------------------------------------------------------------------------
# Helper: resolve site ID
# ---------------------------------------------------------------------------


def _resolve_site_id(site_id: str | None) -> str:
    """
    Resolve site ID from argument or config.

    Raises SecurityError if no site ID is available.
    """
    if site_id:
        return validate_site_id(site_id)

    config_site = get_site_id()
    if config_site:
        return validate_site_id(config_site)

    msg = (
        "site_id is required. Either pass it explicitly or configure "
        "a default via: python -m childermass.network_mcp.auth --setup"
    )
    raise SecurityError(msg)


# ---------------------------------------------------------------------------
# Application Info
# ---------------------------------------------------------------------------


def get_app_info() -> NetworkInfo:
    """Get application version information."""
    rate_limiter.check("info")

    data = _session.get_json(f"{_API_PREFIX}/info")
    if not isinstance(data, dict):
        msg = "Unexpected info response format"
        raise RuntimeError(msg)

    info = NetworkInfo(
        version=data.get("version", "unknown"),
    )

    audit_log("get_app_info", details={"version": info.version})
    return info


# ---------------------------------------------------------------------------
# Network Operations
# ---------------------------------------------------------------------------


def _parse_network(net: dict) -> Network:
    """Parse a network dict into a Network dataclass."""
    dhcp = net.get("dhcpGuarding", {}) or {}
    return Network(
        id=net.get("id", ""),
        name=net.get("name", "Unknown"),
        enabled=net.get("enabled", True),
        vlan_id=net.get("vlanId"),
        is_default=net.get("default", False),
        management=net.get("management"),
        dhcp_guarding_enabled=bool(dhcp.get("trustedDhcpServerIpAddresses")),
        trusted_dhcp_servers=dhcp.get("trustedDhcpServerIpAddresses", []),
    )


def list_networks(
    site_id: str | None = None,
    filter_expr: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[Network]:
    """
    List all networks for a site.

    Args:
        site_id: Site UUID (uses default from config if not provided)
        filter_expr: Optional filter expression (UniFi filter DSL)
        limit: Max results (default 50, max 200)
        offset: Pagination offset
    """
    sid = _resolve_site_id(site_id)
    limit = validate_max_results(limit)
    offset = validate_offset(offset)
    filter_expr = validate_filter_expression(filter_expr)

    rate_limiter.check("networks")

    params: dict = {"limit": limit, "offset": offset}
    if filter_expr:
        params["filter"] = filter_expr

    data = _session.get_json(
        f"{_API_PREFIX}/sites/{sid}/networks",
        params=params,
    )

    if not isinstance(data, dict):
        msg = "Unexpected networks response format"
        raise RuntimeError(msg)

    networks = [_parse_network(n) for n in data.get("data", [])]

    audit_log(
        "list_networks",
        details={
            "site_id": sid,
            "count": len(networks),
        },
    )

    return networks


def get_network(
    network_id: str,
    site_id: str | None = None,
) -> Network:
    """Get details for a specific network."""
    sid = _resolve_site_id(site_id)
    network_id = validate_network_id(network_id)

    rate_limiter.check("networks")

    data = _session.get_json(
        f"{_API_PREFIX}/sites/{sid}/networks/{network_id}",
    )

    if not isinstance(data, dict):
        msg = "Unexpected network response format"
        raise RuntimeError(msg)

    network = _parse_network(data)

    audit_log(
        "get_network",
        details={
            "site_id": sid,
            "network_id": network_id,
            "name": network.name,
        },
    )

    return network


def get_network_references(
    network_id: str,
    site_id: str | None = None,
) -> NetworkReference:
    """Get references (clients, devices) for a network."""
    sid = _resolve_site_id(site_id)
    network_id = validate_network_id(network_id)

    rate_limiter.check("networks")

    data = _session.get_json(
        f"{_API_PREFIX}/sites/{sid}/networks/{network_id}/references",
    )

    if not isinstance(data, dict):
        data = {}

    # Get network name for context
    try:
        net = get_network(network_id, site_id=sid)
        name = net.name
    except Exception:
        name = network_id

    ref = NetworkReference(
        network_id=network_id,
        network_name=name,
        references=data.get("data", []) if isinstance(data.get("data"), list) else [],
    )

    audit_log(
        "get_network_references",
        details={
            "site_id": sid,
            "network_id": network_id,
        },
    )

    return ref


def create_network(
    name: str,
    site_id: str | None = None,
    vlan_id: int | None = None,
    enabled: bool = True,
) -> Network:
    """
    Create a new network.

    Args:
        name: Network name
        site_id: Site UUID
        vlan_id: Optional VLAN ID (1-4094)
        enabled: Whether the network is enabled
    """
    sid = _resolve_site_id(site_id)
    name = validate_network_name(name)
    if vlan_id is not None:
        vlan_id = validate_vlan_id(vlan_id)

    rate_limiter.check("write")

    body: dict = {"name": name, "enabled": enabled}
    if vlan_id is not None:
        body["vlanId"] = vlan_id

    resp = _session.post(
        f"{_API_PREFIX}/sites/{sid}/networks",
        json=body,
    )
    resp.raise_for_status()
    data = resp.json()

    network = _parse_network(data)

    audit_log(
        "create_network",
        details={
            "site_id": sid,
            "name": name,
            "vlan_id": vlan_id,
            "network_id": network.id,
        },
    )

    return network


def update_network(
    network_id: str,
    site_id: str | None = None,
    name: str | None = None,
    vlan_id: int | None = None,
    enabled: bool | None = None,
) -> Network:
    """
    Update an existing network.

    Only provided fields are updated.
    """
    sid = _resolve_site_id(site_id)
    network_id = validate_network_id(network_id)

    if name is not None:
        name = validate_network_name(name)
    if vlan_id is not None:
        vlan_id = validate_vlan_id(vlan_id)

    rate_limiter.check("write")

    # First get current state
    current = _session.get_json(
        f"{_API_PREFIX}/sites/{sid}/networks/{network_id}",
    )
    if not isinstance(current, dict):
        msg = "Unexpected network response format"
        raise RuntimeError(msg)

    # Apply updates
    if name is not None:
        current["name"] = name
    if vlan_id is not None:
        current["vlanId"] = vlan_id
    if enabled is not None:
        current["enabled"] = enabled

    resp = _session.put(
        f"{_API_PREFIX}/sites/{sid}/networks/{network_id}",
        json=current,
    )
    resp.raise_for_status()
    data = resp.json()

    network = _parse_network(data)

    audit_log(
        "update_network",
        details={
            "site_id": sid,
            "network_id": network_id,
            "updates": {
                k: v
                for k, v in {"name": name, "vlan_id": vlan_id, "enabled": enabled}.items()
                if v is not None
            },
        },
    )

    return network


def delete_network(
    network_id: str,
    site_id: str | None = None,
    force: bool = False,
) -> bool:
    """
    Delete a network.

    Args:
        network_id: Network UUID
        site_id: Site UUID
        force: Force deletion even if network has references
    """
    sid = _resolve_site_id(site_id)
    network_id = validate_network_id(network_id)

    rate_limiter.check("write")

    params = {}
    if force:
        params["force"] = "true"

    resp = _session.delete(
        f"{_API_PREFIX}/sites/{sid}/networks/{network_id}",
        params=params,
    )
    resp.raise_for_status()

    audit_log(
        "delete_network",
        details={
            "site_id": sid,
            "network_id": network_id,
            "force": force,
        },
    )

    return True


# ---------------------------------------------------------------------------
# Firewall Policy Operations
# ---------------------------------------------------------------------------


def _parse_policy(pol: dict) -> FirewallPolicy:
    """Parse a firewall policy dict into a FirewallPolicy dataclass."""
    action = pol.get("action", {})
    source = pol.get("source", {})
    dest = pol.get("destination", {})
    ip_scope = pol.get("ipProtocolScope", {})
    schedule = pol.get("schedule", {})

    return FirewallPolicy(
        id=pol.get("id", ""),
        name=pol.get("name", "Unknown"),
        enabled=pol.get("enabled", True),
        description=pol.get("description", ""),
        index=pol.get("index", 0),
        action=action.get("type", "UNKNOWN"),
        source_zone_id=source.get("zoneId", ""),
        destination_zone_id=dest.get("zoneId", ""),
        ip_version=ip_scope.get("ipVersion", "BOTH"),
        logging_enabled=pol.get("loggingEnabled", False),
        schedule_mode=schedule.get("mode", "ALWAYS"),
        connection_states=pol.get("connectionStateFilter", []),
        ipsec_filter=pol.get("ipsecFilter"),
    )


def list_firewall_policies(
    site_id: str | None = None,
    filter_expr: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[FirewallPolicy]:
    """
    List firewall policies for a site.

    Args:
        site_id: Site UUID
        filter_expr: Optional filter expression
        limit: Max results
        offset: Pagination offset
    """
    sid = _resolve_site_id(site_id)
    limit = validate_max_results(limit)
    offset = validate_offset(offset)
    filter_expr = validate_filter_expression(filter_expr)

    rate_limiter.check("firewall")

    params: dict = {"limit": limit, "offset": offset}
    if filter_expr:
        params["filter"] = filter_expr

    data = _session.get_json(
        f"{_API_PREFIX}/sites/{sid}/firewall/policies",
        params=params,
    )

    if not isinstance(data, dict):
        msg = "Unexpected firewall policies response format"
        raise RuntimeError(msg)

    policies = [_parse_policy(p) for p in data.get("data", [])]

    audit_log(
        "list_firewall_policies",
        details={
            "site_id": sid,
            "count": len(policies),
        },
    )

    return policies


def get_firewall_policy(
    policy_id: str,
    site_id: str | None = None,
) -> FirewallPolicy:
    """Get details for a specific firewall policy."""
    sid = _resolve_site_id(site_id)
    policy_id = validate_policy_id(policy_id)

    rate_limiter.check("firewall")

    data = _session.get_json(
        f"{_API_PREFIX}/sites/{sid}/firewall/policies/{policy_id}",
    )

    if not isinstance(data, dict):
        msg = "Unexpected policy response format"
        raise RuntimeError(msg)

    policy = _parse_policy(data)

    audit_log(
        "get_firewall_policy",
        details={
            "site_id": sid,
            "policy_id": policy_id,
            "name": policy.name,
        },
    )

    return policy


def create_firewall_policy(
    name: str,
    action: str,
    source_zone_id: str,
    destination_zone_id: str,
    site_id: str | None = None,
    enabled: bool = True,
    description: str = "",
    ip_version: str = "BOTH",
    logging_enabled: bool = False,
) -> FirewallPolicy:
    """
    Create a new firewall policy.

    Args:
        name: Policy name
        action: Action type (ALLOW, DROP, REJECT)
        source_zone_id: Source zone UUID
        destination_zone_id: Destination zone UUID
        site_id: Site UUID
        enabled: Whether the policy is enabled
        description: Optional description
        ip_version: IP version scope (IPv4, IPv6, BOTH)
        logging_enabled: Whether to log matches
    """
    sid = _resolve_site_id(site_id)
    name = validate_policy_name(name)
    action = validate_policy_action(action)
    source_zone_id = validate_zone_id(source_zone_id)
    destination_zone_id = validate_zone_id(destination_zone_id)

    rate_limiter.check("write")

    body = {
        "name": name,
        "enabled": enabled,
        "description": description,
        "action": {"type": action},
        "source": {"zoneId": source_zone_id},
        "destination": {"zoneId": destination_zone_id},
        "ipProtocolScope": {"ipVersion": ip_version},
        "loggingEnabled": logging_enabled,
        "schedule": {"mode": "ALWAYS"},
    }

    resp = _session.post(
        f"{_API_PREFIX}/sites/{sid}/firewall/policies",
        json=body,
    )
    resp.raise_for_status()
    data = resp.json()

    policy = _parse_policy(data)

    audit_log(
        "create_firewall_policy",
        details={
            "site_id": sid,
            "name": name,
            "action": action,
            "policy_id": policy.id,
        },
    )

    return policy


def update_firewall_policy(
    policy_id: str,
    site_id: str | None = None,
    name: str | None = None,
    enabled: bool | None = None,
    description: str | None = None,
    action: str | None = None,
    logging_enabled: bool | None = None,
) -> FirewallPolicy:
    """
    Update an existing firewall policy.

    Only provided fields are updated.
    """
    sid = _resolve_site_id(site_id)
    policy_id = validate_policy_id(policy_id)

    if name is not None:
        name = validate_policy_name(name)
    if action is not None:
        action = validate_policy_action(action)

    rate_limiter.check("write")

    # Get current state
    current = _session.get_json(
        f"{_API_PREFIX}/sites/{sid}/firewall/policies/{policy_id}",
    )
    if not isinstance(current, dict):
        msg = "Unexpected policy response format"
        raise RuntimeError(msg)

    # Apply updates
    if name is not None:
        current["name"] = name
    if enabled is not None:
        current["enabled"] = enabled
    if description is not None:
        current["description"] = description
    if action is not None:
        current["action"] = {"type": action}
    if logging_enabled is not None:
        current["loggingEnabled"] = logging_enabled

    resp = _session.put(
        f"{_API_PREFIX}/sites/{sid}/firewall/policies/{policy_id}",
        json=current,
    )
    resp.raise_for_status()
    data = resp.json()

    policy = _parse_policy(data)

    audit_log(
        "update_firewall_policy",
        details={
            "site_id": sid,
            "policy_id": policy_id,
            "updates": {
                k: v
                for k, v in {
                    "name": name,
                    "enabled": enabled,
                    "action": action,
                    "logging": logging_enabled,
                }.items()
                if v is not None
            },
        },
    )

    return policy


def delete_firewall_policy(
    policy_id: str,
    site_id: str | None = None,
) -> bool:
    """Delete a firewall policy."""
    sid = _resolve_site_id(site_id)
    policy_id = validate_policy_id(policy_id)

    rate_limiter.check("write")

    resp = _session.delete(
        f"{_API_PREFIX}/sites/{sid}/firewall/policies/{policy_id}",
    )
    resp.raise_for_status()

    audit_log(
        "delete_firewall_policy",
        details={
            "site_id": sid,
            "policy_id": policy_id,
        },
    )

    return True


def get_policy_ordering(
    site_id: str | None = None,
) -> PolicyOrdering:
    """Get the current firewall policy ordering."""
    sid = _resolve_site_id(site_id)

    rate_limiter.check("firewall")

    data = _session.get_json(
        f"{_API_PREFIX}/sites/{sid}/firewall/policies/ordering",
    )

    if not isinstance(data, dict):
        msg = "Unexpected ordering response format"
        raise RuntimeError(msg)

    ordering = PolicyOrdering(
        policy_ids=data.get("data", []),
    )

    audit_log("get_policy_ordering", details={"site_id": sid})

    return ordering


def set_policy_ordering(
    policy_ids: list[str],
    site_id: str | None = None,
) -> bool:
    """
    Set the firewall policy ordering.

    Args:
        policy_ids: Ordered list of policy UUIDs
        site_id: Site UUID
    """
    sid = _resolve_site_id(site_id)

    # Validate each policy ID
    validated_ids = [validate_policy_id(pid) for pid in policy_ids]

    rate_limiter.check("write")

    resp = _session.put(
        f"{_API_PREFIX}/sites/{sid}/firewall/policies/ordering",
        json={"data": validated_ids},
    )
    resp.raise_for_status()

    audit_log(
        "set_policy_ordering",
        details={
            "site_id": sid,
            "count": len(validated_ids),
        },
    )

    return True


# ---------------------------------------------------------------------------
# Firewall Zone Operations
# ---------------------------------------------------------------------------


def _parse_zone(zone: dict) -> FirewallZone:
    """Parse a firewall zone dict into a FirewallZone dataclass."""
    return FirewallZone(
        id=zone.get("id", ""),
        name=zone.get("name", "Unknown"),
    )


def list_firewall_zones(
    site_id: str | None = None,
) -> list[FirewallZone]:
    """List all firewall zones for a site."""
    sid = _resolve_site_id(site_id)

    rate_limiter.check("firewall")

    data = _session.get_json(
        f"{_API_PREFIX}/sites/{sid}/firewall/zones",
    )

    if not isinstance(data, dict):
        msg = "Unexpected zones response format"
        raise RuntimeError(msg)

    zones = [_parse_zone(z) for z in data.get("data", [])]

    audit_log(
        "list_firewall_zones",
        details={
            "site_id": sid,
            "count": len(zones),
        },
    )

    return zones


def get_firewall_zone(
    zone_id: str,
    site_id: str | None = None,
) -> FirewallZone:
    """Get details for a specific firewall zone."""
    sid = _resolve_site_id(site_id)
    zone_id = validate_zone_id(zone_id)

    rate_limiter.check("firewall")

    data = _session.get_json(
        f"{_API_PREFIX}/sites/{sid}/firewall/zones/{zone_id}",
    )

    if not isinstance(data, dict):
        msg = "Unexpected zone response format"
        raise RuntimeError(msg)

    zone = _parse_zone(data)

    audit_log(
        "get_firewall_zone",
        details={
            "site_id": sid,
            "zone_id": zone_id,
            "name": zone.name,
        },
    )

    return zone


def create_firewall_zone(
    name: str,
    site_id: str | None = None,
) -> FirewallZone:
    """Create a custom firewall zone."""
    sid = _resolve_site_id(site_id)
    name = validate_network_name(name)  # reuse network name validation

    rate_limiter.check("write")

    resp = _session.post(
        f"{_API_PREFIX}/sites/{sid}/firewall/zones",
        json={"name": name},
    )
    resp.raise_for_status()
    data = resp.json()

    zone = _parse_zone(data)

    audit_log(
        "create_firewall_zone",
        details={
            "site_id": sid,
            "name": name,
            "zone_id": zone.id,
        },
    )

    return zone


def update_firewall_zone(
    zone_id: str,
    name: str,
    site_id: str | None = None,
) -> FirewallZone:
    """Update a custom firewall zone."""
    sid = _resolve_site_id(site_id)
    zone_id = validate_zone_id(zone_id)
    name = validate_network_name(name)

    rate_limiter.check("write")

    resp = _session.put(
        f"{_API_PREFIX}/sites/{sid}/firewall/zones/{zone_id}",
        json={"name": name},
    )
    resp.raise_for_status()
    data = resp.json()

    zone = _parse_zone(data)

    audit_log(
        "update_firewall_zone",
        details={
            "site_id": sid,
            "zone_id": zone_id,
            "name": name,
        },
    )

    return zone


def delete_firewall_zone(
    zone_id: str,
    site_id: str | None = None,
) -> bool:
    """Delete a custom firewall zone."""
    sid = _resolve_site_id(site_id)
    zone_id = validate_zone_id(zone_id)

    rate_limiter.check("write")

    resp = _session.delete(
        f"{_API_PREFIX}/sites/{sid}/firewall/zones/{zone_id}",
    )
    resp.raise_for_status()

    audit_log(
        "delete_firewall_zone",
        details={
            "site_id": sid,
            "zone_id": zone_id,
        },
    )

    return True


# ---------------------------------------------------------------------------
# Voucher Operations
# ---------------------------------------------------------------------------


def _parse_voucher(v: dict) -> Voucher:
    """Parse a voucher dict into a Voucher dataclass."""
    return Voucher(
        id=v.get("id", ""),
        name=v.get("name"),
        code=v.get("code", ""),
        created_at=v.get("createdAt"),
        activated_at=v.get("activatedAt"),
        expires_at=v.get("expiresAt"),
        expired=v.get("expired", False),
        time_limit_minutes=v.get("timeLimitMinutes"),
        data_limit_mb=v.get("dataUsageLimitMBytes"),
        download_limit_kbps=v.get("rxRateLimitKbps"),
        upload_limit_kbps=v.get("txRateLimitKbps"),
        guest_limit=v.get("authorizedGuestLimit"),
        guest_count=v.get("authorizedGuestCount", 0),
    )


def list_vouchers(
    site_id: str | None = None,
    filter_expr: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[Voucher]:
    """
    List hotspot vouchers for a site.

    Args:
        site_id: Site UUID
        filter_expr: Optional filter expression
        limit: Max results
        offset: Pagination offset
    """
    sid = _resolve_site_id(site_id)
    limit = validate_max_results(limit)
    offset = validate_offset(offset)
    filter_expr = validate_filter_expression(filter_expr)

    rate_limiter.check("vouchers")

    params: dict = {"limit": limit, "offset": offset}
    if filter_expr:
        params["filter"] = filter_expr

    data = _session.get_json(
        f"{_API_PREFIX}/sites/{sid}/hotspot/vouchers",
        params=params,
    )

    if not isinstance(data, dict):
        msg = "Unexpected vouchers response format"
        raise RuntimeError(msg)

    vouchers = [_parse_voucher(v) for v in data.get("data", [])]

    audit_log(
        "list_vouchers",
        details={
            "site_id": sid,
            "count": len(vouchers),
        },
    )

    return vouchers


def get_voucher(
    voucher_id: str,
    site_id: str | None = None,
) -> Voucher:
    """Get details for a specific voucher."""
    sid = _resolve_site_id(site_id)
    voucher_id = validate_voucher_id(voucher_id)

    rate_limiter.check("vouchers")

    data = _session.get_json(
        f"{_API_PREFIX}/sites/{sid}/hotspot/vouchers/{voucher_id}",
    )

    if not isinstance(data, dict):
        msg = "Unexpected voucher response format"
        raise RuntimeError(msg)

    voucher = _parse_voucher(data)

    audit_log(
        "get_voucher",
        details={
            "site_id": sid,
            "voucher_id": voucher_id,
        },
    )

    return voucher


def generate_vouchers(
    site_id: str | None = None,
    name: str | None = None,
    count: int = 1,
    time_limit_minutes: int | None = None,
    data_limit_mb: int | None = None,
    download_limit_kbps: int | None = None,
    upload_limit_kbps: int | None = None,
    guest_limit: int | None = None,
) -> list[Voucher]:
    """
    Generate new hotspot vouchers.

    Args:
        site_id: Site UUID
        name: Optional voucher name/label
        count: Number of vouchers to generate (default 1, max 1000)
        time_limit_minutes: Time limit in minutes (max ~1 year)
        data_limit_mb: Data usage limit in MB
        download_limit_kbps: Download speed limit in kbps
        upload_limit_kbps: Upload speed limit in kbps
        guest_limit: Max simultaneous guests per voucher
    """
    sid = _resolve_site_id(site_id)

    validated = validate_voucher_params(
        time_limit_minutes=time_limit_minutes,
        data_limit_mb=data_limit_mb,
        download_limit_kbps=download_limit_kbps,
        upload_limit_kbps=upload_limit_kbps,
        guest_limit=guest_limit,
        count=count,
    )

    rate_limiter.check("write")

    body: dict = {}
    if name:
        body["name"] = name
    body.update(validated)

    resp = _session.post(
        f"{_API_PREFIX}/sites/{sid}/hotspot/vouchers",
        json=body,
    )
    resp.raise_for_status()
    data = resp.json()

    if isinstance(data, dict):
        raw_vouchers = data.get("data", [])
    elif isinstance(data, list):
        raw_vouchers = data
    else:
        raw_vouchers = []

    vouchers = [_parse_voucher(v) for v in raw_vouchers]

    audit_log(
        "generate_vouchers",
        details={
            "site_id": sid,
            "count": len(vouchers),
            "name": name,
        },
    )

    return vouchers


def delete_voucher(
    voucher_id: str,
    site_id: str | None = None,
) -> bool:
    """Delete a single voucher."""
    sid = _resolve_site_id(site_id)
    voucher_id = validate_voucher_id(voucher_id)

    rate_limiter.check("write")

    resp = _session.delete(
        f"{_API_PREFIX}/sites/{sid}/hotspot/vouchers/{voucher_id}",
    )
    resp.raise_for_status()

    audit_log(
        "delete_voucher",
        details={
            "site_id": sid,
            "voucher_id": voucher_id,
        },
    )

    return True


def delete_vouchers_bulk(
    site_id: str | None = None,
    filter_expr: str | None = None,
) -> bool:
    """
    Delete vouchers in bulk.

    Args:
        site_id: Site UUID
        filter_expr: Optional filter to select vouchers to delete
    """
    sid = _resolve_site_id(site_id)
    filter_expr = validate_filter_expression(filter_expr)

    rate_limiter.check("write")

    params = {}
    if filter_expr:
        params["filter"] = filter_expr

    resp = _session.delete(
        f"{_API_PREFIX}/sites/{sid}/hotspot/vouchers",
        params=params,
    )
    resp.raise_for_status()

    audit_log(
        "delete_vouchers_bulk",
        details={
            "site_id": sid,
            "filter": filter_expr,
        },
    )

    return True


# ---------------------------------------------------------------------------
# System Status (combined overview)
# ---------------------------------------------------------------------------


def get_network_status(
    site_id: str | None = None,
) -> dict:
    """
    Get combined network status overview.

    Combines app info, network list, firewall summary, and voucher summary
    for a quick health check.
    """
    sid = _resolve_site_id(site_id)

    rate_limiter.check("read")

    # Gather data
    info = get_app_info()
    networks = list_networks(site_id=sid)
    policies = list_firewall_policies(site_id=sid)
    zones = list_firewall_zones(site_id=sid)
    vouchers = list_vouchers(site_id=sid)

    # Check for issues
    issues: list[str] = []

    disabled_networks = [n for n in networks if not n.enabled]
    if disabled_networks:
        issues.append(
            f"{len(disabled_networks)} network(s) disabled: "
            + ", ".join(n.name for n in disabled_networks)
        )

    disabled_policies = [p for p in policies if not p.enabled]
    if disabled_policies:
        issues.append(
            f"{len(disabled_policies)} firewall policy/ies disabled: "
            + ", ".join(p.name for p in disabled_policies)
        )

    expired_vouchers = [v for v in vouchers if v.expired]
    active_vouchers = [v for v in vouchers if not v.expired]

    status = {
        "app_version": info.version,
        "site_id": sid,
        "networks": {
            "total": len(networks),
            "enabled": sum(1 for n in networks if n.enabled),
            "list": [
                {
                    "name": n.name,
                    "vlan_id": n.vlan_id,
                    "enabled": n.enabled,
                    "default": n.is_default,
                }
                for n in networks
            ],
        },
        "firewall": {
            "total_policies": len(policies),
            "enabled_policies": sum(1 for p in policies if p.enabled),
            "zones": len(zones),
            "zone_list": [{"name": z.name, "id": z.id} for z in zones],
        },
        "vouchers": {
            "total": len(vouchers),
            "active": len(active_vouchers),
            "expired": len(expired_vouchers),
        },
        "issues": issues,
        "all_ok": len(issues) == 0,
    }

    audit_log("get_network_status", details={"site_id": sid})

    return status


# ---------------------------------------------------------------------------
# Classic API helper
# ---------------------------------------------------------------------------


def _classic_path(site_name: str = "default") -> str:
    """Build the classic API path prefix for a site."""
    return f"{_CLASSIC_PREFIX}/{site_name}"


def _resolve_site_name() -> str:
    """
    Resolve the site *name* used by the classic API.

    The classic API uses the site name (usually "default"), not the UUID.
    We store it in config as ``site_name``.  Falls back to ``"default"``.
    """
    from .auth import load_config

    config = load_config()
    if config and config.get("site_name"):
        return config["site_name"]
    return "default"


# ---------------------------------------------------------------------------
# Classic API: Health / System
# ---------------------------------------------------------------------------


def _parse_health(data: list[dict]) -> HealthStatus:
    """Parse ``/stat/health`` response into HealthStatus."""
    by_sub: dict[str, dict] = {}
    for item in data:
        by_sub[item.get("subsystem", "")] = item

    www = by_sub.get("www", {})
    wan = by_sub.get("wan", {})
    _lan = by_sub.get("lan", {})
    _wlan = by_sub.get("wlan", {})

    return HealthStatus(
        status=www.get("status", "unknown"),
        num_ap=int(by_sub.get("wlan", {}).get("num_ap", 0)),
        num_adopted=int(by_sub.get("wlan", {}).get("num_adopted", 0)),
        num_disconnected=int(by_sub.get("wlan", {}).get("num_disconnected", 0)),
        num_pending=int(by_sub.get("wlan", {}).get("num_pending", 0)),
        num_gw=int(wan.get("num_gw", 0)),
        num_sw=int(by_sub.get("lan", {}).get("num_sw", 0)),
        wan_ip=wan.get("wan_ip", ""),
        lan_ip=_lan.get("lan_ip", ""),
        isp_name=wan.get("isp_name", ""),
        uptime_seconds=int(www.get("latency", wan.get("gw_system_stats", {}).get("uptime", 0))),
        latency_ms=int(www.get("latency", 0)),
        download_speed_mbps=float(www.get("xput_down", 0)),
        upload_speed_mbps=float(www.get("xput_up", 0)),
        mem_used_pct=float(wan.get("gw_system_stats", {}).get("mem", 0)),
        cpu_used_pct=float(wan.get("gw_system_stats", {}).get("cpu", 0)),
        subsystems={k: v.get("status", "unknown") for k, v in by_sub.items()},
    )


def get_site_health() -> HealthStatus:
    """
    Get overall site health from the classic API.

    Endpoint: GET /proxy/network/api/s/{site}/stat/health
    """
    rate_limiter.check("stats")

    site = _resolve_site_name()
    data = _session.get_json(f"{_classic_path(site)}/stat/health")

    if isinstance(data, dict):
        items = data.get("data", [])
    elif isinstance(data, list):
        items = data
    else:
        items = []

    health = _parse_health(items)

    audit_log("get_site_health", details={"status": health.status})
    return health


# ---------------------------------------------------------------------------
# Classic API: Active Clients
# ---------------------------------------------------------------------------


def _parse_client(c: dict) -> ActiveClient:
    """Parse a single client dict from ``/stat/sta``."""
    return ActiveClient(
        mac=c.get("mac", ""),
        hostname=c.get("hostname", c.get("name", "")),
        ip=c.get("ip", ""),
        network=c.get("network", c.get("essid", "")),
        is_wired=c.get("is_wired", False),
        rx_bytes=int(c.get("rx_bytes", 0)),
        tx_bytes=int(c.get("tx_bytes", 0)),
        uptime_seconds=int(c.get("uptime", 0)),
        last_seen=int(c.get("last_seen", 0)),
        signal=c.get("signal") if not c.get("is_wired") else None,
        satisfaction=c.get("satisfaction"),
        oui=c.get("oui", ""),
        blocked=c.get("blocked", False),
        noted=c.get("noted", False),
        name=c.get("name"),
    )


def list_active_clients() -> list[ActiveClient]:
    """
    List all currently active (online) clients.

    Endpoint: GET /proxy/network/api/s/{site}/stat/sta
    """
    rate_limiter.check("clients")

    site = _resolve_site_name()
    data = _session.get_json(f"{_classic_path(site)}/stat/sta")

    if isinstance(data, dict):
        items = data.get("data", [])
    else:
        items = []

    clients = [_parse_client(c) for c in items]

    audit_log("list_active_clients", details={"count": len(clients)})
    return clients


def get_client_details(mac: str) -> ActiveClient:
    """
    Get details for a specific client by MAC address.

    Endpoint: GET /proxy/network/api/s/{site}/stat/sta/{mac}
    """
    mac = validate_mac_address(mac)
    rate_limiter.check("clients")

    site = _resolve_site_name()
    data = _session.get_json(f"{_classic_path(site)}/stat/sta/{mac}")

    if isinstance(data, dict):
        items = data.get("data", [])
    else:
        items = []

    if not items:
        msg = f"Client {mac} not found or not online"
        raise RuntimeError(msg)

    client_obj = _parse_client(items[0])

    audit_log("get_client_details", details={"mac": mac})
    return client_obj


def get_client_history(mac: str, hours: int = 24) -> list[dict]:
    """
    Get traffic history for a client (hourly buckets).

    Endpoint: POST /proxy/network/api/s/{site}/stat/report/hourly.sta
    """
    mac = validate_mac_address(mac)
    hours = validate_history_hours(hours)
    rate_limiter.check("clients")

    import time as _time

    end = int(_time.time())
    start = end - (hours * 3600)

    site = _resolve_site_name()
    data = _session.post(
        f"{_classic_path(site)}/stat/report/hourly.sta",
        json={
            "attrs": ["rx_bytes", "tx_bytes", "time"],
            "start": start,
            "end": end,
            "mac": mac,
        },
    )
    data.raise_for_status()
    resp = data.json()

    items = resp.get("data", []) if isinstance(resp, dict) else []

    audit_log("get_client_history", details={"mac": mac, "hours": hours})
    return items


def block_client(mac: str) -> bool:
    """
    Block a client by MAC address.

    Endpoint: POST /proxy/network/api/s/{site}/cmd/stamgr  {cmd: "block-sta"}
    """
    mac = validate_mac_address(mac)
    rate_limiter.check("write")

    site = _resolve_site_name()
    resp = _session.post(
        f"{_classic_path(site)}/cmd/stamgr",
        json={"cmd": "block-sta", "mac": mac},
    )
    resp.raise_for_status()

    audit_log("block_client", details={"mac": mac})
    return True


def unblock_client(mac: str) -> bool:
    """
    Unblock a previously blocked client.

    Endpoint: POST /proxy/network/api/s/{site}/cmd/stamgr  {cmd: "unblock-sta"}
    """
    mac = validate_mac_address(mac)
    rate_limiter.check("write")

    site = _resolve_site_name()
    resp = _session.post(
        f"{_classic_path(site)}/cmd/stamgr",
        json={"cmd": "unblock-sta", "mac": mac},
    )
    resp.raise_for_status()

    audit_log("unblock_client", details={"mac": mac})
    return True


def reconnect_client(mac: str) -> bool:
    """
    Force-reconnect (kick) a wireless client.

    Endpoint: POST /proxy/network/api/s/{site}/cmd/stamgr  {cmd: "kick-sta"}
    """
    mac = validate_mac_address(mac)
    rate_limiter.check("write")

    site = _resolve_site_name()
    resp = _session.post(
        f"{_classic_path(site)}/cmd/stamgr",
        json={"cmd": "kick-sta", "mac": mac},
    )
    resp.raise_for_status()

    audit_log("reconnect_client", details={"mac": mac})
    return True


# ---------------------------------------------------------------------------
# Classic API: Devices
# ---------------------------------------------------------------------------


def _parse_device(d: dict) -> DeviceInfo:
    """Parse a device dict from ``/stat/device``."""
    sys_stats = d.get("system-stats", d.get("sys_stats", {}))
    return DeviceInfo(
        mac=d.get("mac", ""),
        model=d.get("model", ""),
        name=d.get("name", d.get("hostname", "")),
        type=d.get("type", ""),
        adopted=d.get("adopted", False),
        state=int(d.get("state", 0)),
        ip=d.get("ip", ""),
        version=d.get("version", ""),
        uptime_seconds=int(d.get("uptime", 0)),
        last_seen=int(d.get("last_seen", 0)),
        satisfaction=d.get("satisfaction"),
        num_clients=int(d.get("num_sta", 0)),
        cpu_used_pct=float(sys_stats.get("cpu", 0)),
        mem_used_pct=float(sys_stats.get("mem", 0)),
    )


def list_devices() -> list[DeviceInfo]:
    """
    List all adopted UniFi devices (APs, switches, gateways).

    Endpoint: GET /proxy/network/api/s/{site}/stat/device
    """
    rate_limiter.check("devices")

    site = _resolve_site_name()
    data = _session.get_json(f"{_classic_path(site)}/stat/device")

    if isinstance(data, dict):
        items = data.get("data", [])
    else:
        items = []

    devices = [_parse_device(d) for d in items]

    audit_log("list_devices", details={"count": len(devices)})
    return devices


def get_device_details(mac: str) -> DeviceInfo:
    """
    Get details for a specific device by MAC.

    Endpoint: GET /proxy/network/api/s/{site}/stat/device/{mac}
    """
    mac = validate_mac_address(mac, "Device MAC")
    rate_limiter.check("devices")

    site = _resolve_site_name()
    data = _session.get_json(f"{_classic_path(site)}/stat/device/{mac}")

    if isinstance(data, dict):
        items = data.get("data", [])
    else:
        items = []

    if not items:
        msg = f"Device {mac} not found"
        raise RuntimeError(msg)

    device = _parse_device(items[0])

    audit_log("get_device_details", details={"mac": mac})
    return device


def restart_device(mac: str) -> bool:
    """
    Restart (reboot) a UniFi device.

    Endpoint: POST /proxy/network/api/s/{site}/cmd/devmgr  {cmd: "restart", mac}
    """
    mac = validate_mac_address(mac, "Device MAC")
    rate_limiter.check("write")

    site = _resolve_site_name()
    resp = _session.post(
        f"{_classic_path(site)}/cmd/devmgr",
        json={"cmd": "restart", "mac": mac},
    )
    resp.raise_for_status()

    audit_log("restart_device", details={"mac": mac})
    return True


# ---------------------------------------------------------------------------
# Classic API: Traffic Statistics
# ---------------------------------------------------------------------------


def _parse_site_stat(s: dict) -> SiteStats:
    """Parse a single time-bucket from ``/stat/report/…``."""
    return SiteStats(
        time_epoch=int(s.get("time", 0)),
        wan_rx_bytes=int(s.get("wan-rx_bytes", s.get("rx_bytes", 0))),
        wan_tx_bytes=int(s.get("wan-tx_bytes", s.get("tx_bytes", 0))),
        num_sta=int(s.get("num_sta", 0)),
        lan_num_sta=int(s.get("lan-num_sta", 0)),
        wlan_num_sta=int(s.get("wlan-num_sta", 0)),
    )


def get_site_stats(
    period: str = "hourly",
    start: int | None = None,
    end: int | None = None,
) -> list[SiteStats]:
    """
    Get aggregated site traffic statistics.

    Args:
        period: "hourly", "daily", or "5minutes"
        start: Start epoch (seconds). Default: last 24h
        end: End epoch (seconds). Default: now

    Endpoint: POST /proxy/network/api/s/{site}/stat/report/{period}.site
    """
    period = validate_period(period)
    rate_limiter.check("stats")

    import time as _time

    now = int(_time.time())
    if end is None:
        end = now
    if start is None:
        start = end - 86400  # last 24h

    site = _resolve_site_name()
    resp = _session.post(
        f"{_classic_path(site)}/stat/report/{period}.site",
        json={
            "attrs": [
                "wan-rx_bytes",
                "wan-tx_bytes",
                "num_sta",
                "lan-num_sta",
                "wlan-num_sta",
                "time",
            ],
            "start": start,
            "end": end,
        },
    )
    resp.raise_for_status()
    data = resp.json()

    items = data.get("data", []) if isinstance(data, dict) else []
    stats = [_parse_site_stat(s) for s in items]

    audit_log("get_site_stats", details={"period": period, "count": len(stats)})
    return stats


# ---------------------------------------------------------------------------
# Classic API: DPI (Deep Packet Inspection)
# ---------------------------------------------------------------------------


def _parse_dpi(d: dict) -> DpiStat:
    """Parse a DPI stat entry."""
    return DpiStat(
        cat=int(d.get("cat", 0)),
        app=int(d.get("app", 0)),
        rx_bytes=int(d.get("rx_bytes", 0)),
        tx_bytes=int(d.get("tx_bytes", 0)),
        rx_packets=int(d.get("rx_packets", 0)),
        tx_packets=int(d.get("tx_packets", 0)),
    )


def get_dpi_stats(dpi_type: str = "by_app") -> list[DpiStat]:
    """
    Get DPI (Deep Packet Inspection) traffic statistics.

    Args:
        dpi_type: "by_app" or "by_cat"

    Endpoint: GET /proxy/network/api/s/{site}/stat/dpi
    """
    dpi_type = validate_dpi_type(dpi_type)
    rate_limiter.check("dpi")

    site = _resolve_site_name()
    data = _session.get_json(
        f"{_classic_path(site)}/stat/dpi",
        params={"type": dpi_type},
    )

    if isinstance(data, dict):
        items = data.get("data", [])
    else:
        items = []

    stats = [_parse_dpi(d) for d in items]

    audit_log("get_dpi_stats", details={"type": dpi_type, "count": len(stats)})
    return stats


def get_client_dpi(mac: str) -> list[DpiStat]:
    """
    Get DPI stats for a specific client (per-client app usage).

    Endpoint: GET /proxy/network/api/s/{site}/stat/stadpi
    """
    mac = validate_mac_address(mac)
    rate_limiter.check("dpi")

    site = _resolve_site_name()

    # The stadpi endpoint returns stats filtered by MAC
    resp = _session.post(
        f"{_classic_path(site)}/stat/stadpi",
        json={"mac": mac, "type": "by_app"},
    )
    resp.raise_for_status()
    data = resp.json()

    items = data.get("data", []) if isinstance(data, dict) else []
    stats = [_parse_dpi(d) for d in items]

    audit_log("get_client_dpi", details={"mac": mac, "count": len(stats)})
    return stats


# ---------------------------------------------------------------------------
# Classic API: IPS / Security
# ---------------------------------------------------------------------------


def _parse_ips_event(e: dict) -> IpsEvent:
    """Parse an IPS event from ``/stat/ips/event``."""
    return IpsEvent(
        timestamp=int(e.get("timestamp", e.get("time", 0))),
        key=e.get("key", ""),
        msg=e.get("msg", e.get("message", "")),
        src_ip=e.get("src_ip", e.get("srcipGeo", {}).get("ip", "")),
        dst_ip=e.get("dst_ip", e.get("dstipGeo", {}).get("ip", "")),
        src_port=e.get("src_port"),
        dst_port=e.get("dst_port"),
        proto=e.get("proto", ""),
        catname=e.get("catname", e.get("category", "")),
        action=e.get("action", ""),
        in_iface=e.get("in_iface", ""),
        archived=e.get("archived", False),
    )


def list_ips_events(limit: int = 100) -> list[IpsEvent]:
    """
    List recent IPS (Intrusion Prevention System) events / alerts.

    Args:
        limit: Max events to return (default 100, max 10000)

    Endpoint: GET /proxy/network/api/s/{site}/stat/ips/event
    """
    limit = validate_event_limit(limit)
    rate_limiter.check("security")

    site = _resolve_site_name()
    data = _session.get_json(
        f"{_classic_path(site)}/stat/ips/event",
        params={"_limit": limit, "_sort": "-time"},
    )

    if isinstance(data, dict):
        items = data.get("data", [])
    else:
        items = []

    events = [_parse_ips_event(e) for e in items]

    audit_log("list_ips_events", details={"count": len(events)})
    return events


# ---------------------------------------------------------------------------
# Classic API: Rogue APs
# ---------------------------------------------------------------------------


def _parse_rogue_ap(r: dict) -> RogueAp:
    """Parse a rogue AP dict."""
    return RogueAp(
        bssid=r.get("bssid", ""),
        essid=r.get("essid", ""),
        channel=int(r.get("channel", 0)),
        rssi=int(r.get("rssi", 0)),
        security=r.get("security", ""),
        oui=r.get("oui", ""),
        band=r.get("band", r.get("radio", "")),
        age_seconds=int(r.get("age", 0)),
        last_seen=int(r.get("last_seen", 0)),
        ap_mac=r.get("ap_mac", ""),
        is_rogue=r.get("is_rogue", True),
    )


def list_rogue_aps() -> list[RogueAp]:
    """
    List detected rogue / neighboring access points.

    Endpoint: GET /proxy/network/api/s/{site}/stat/rogueap
    """
    rate_limiter.check("security")

    site = _resolve_site_name()
    data = _session.get_json(f"{_classic_path(site)}/stat/rogueap")

    if isinstance(data, dict):
        items = data.get("data", [])
    else:
        items = []

    rogue_aps = [_parse_rogue_ap(r) for r in items]

    audit_log("list_rogue_aps", details={"count": len(rogue_aps)})
    return rogue_aps


# ---------------------------------------------------------------------------
# Classic API: Alarms
# ---------------------------------------------------------------------------


def _parse_alarm(a: dict) -> Alarm:
    """Parse an alarm dict."""
    return Alarm(
        id=a.get("_id", ""),
        key=a.get("key", ""),
        msg=a.get("msg", ""),
        datetime=a.get("datetime", ""),
        archived=a.get("archived", False),
        handled=a.get("handled", a.get("handled_admin_id", "") != ""),
    )


def list_alarms(limit: int = 100, archived: bool = False) -> list[Alarm]:
    """
    List system alarms (security notifications, device issues, etc.).

    Args:
        limit: Max alarms to return
        archived: Include archived alarms

    Endpoint: GET /proxy/network/api/s/{site}/stat/alarm (unarchived)
              GET /proxy/network/api/s/{site}/stat/alarm  (all)
    """
    limit = validate_event_limit(limit)
    rate_limiter.check("security")

    site = _resolve_site_name()
    params: dict = {"_limit": limit, "_sort": "-time"}
    if not archived:
        params["archived"] = "false"

    data = _session.get_json(
        f"{_classic_path(site)}/stat/alarm",
        params=params,
    )

    if isinstance(data, dict):
        items = data.get("data", [])
    else:
        items = []

    alarms = [_parse_alarm(a) for a in items]

    audit_log("list_alarms", details={"count": len(alarms), "archived": archived})
    return alarms


def archive_alarm(alarm_id: str) -> bool:
    """
    Archive (acknowledge) an alarm.

    Endpoint: POST /proxy/network/api/s/{site}/cmd/evtmgr
    """
    if not alarm_id or not isinstance(alarm_id, str):
        msg = "alarm_id is required"
        raise SecurityError(msg)
    alarm_id = alarm_id.strip()

    rate_limiter.check("write")

    site = _resolve_site_name()
    resp = _session.post(
        f"{_classic_path(site)}/cmd/evtmgr",
        json={"cmd": "archive-alarm", "_id": alarm_id},
    )
    resp.raise_for_status()

    audit_log("archive_alarm", details={"alarm_id": alarm_id})
    return True


# ---------------------------------------------------------------------------
# Classic API: Events
# ---------------------------------------------------------------------------


def _parse_event(e: dict) -> Event:
    """Parse an event log entry."""
    return Event(
        id=e.get("_id", ""),
        key=e.get("key", ""),
        msg=e.get("msg", ""),
        datetime=e.get("datetime", ""),
        subsystem=e.get("subsystem", ""),
    )


def list_events(limit: int = 100) -> list[Event]:
    """
    List recent controller events (device connections, client activity, etc.).

    Args:
        limit: Max events to return (default 100, max 10000)

    Endpoint: GET /proxy/network/api/s/{site}/stat/event
    """
    limit = validate_event_limit(limit)
    rate_limiter.check("read")

    site = _resolve_site_name()
    data = _session.get_json(
        f"{_classic_path(site)}/stat/event",
        params={"_limit": limit, "_sort": "-time"},
    )

    if isinstance(data, dict):
        items = data.get("data", [])
    else:
        items = []

    events = [_parse_event(e) for e in items]

    audit_log("list_events", details={"count": len(events)})
    return events


# ---------------------------------------------------------------------------
# Classic API: WiFi / RF
# ---------------------------------------------------------------------------


def _parse_rf_channel(ch: dict) -> RfChannel:
    """Parse an RF channel from a spectrum scan result."""
    return RfChannel(
        channel=int(ch.get("channel", 0)),
        band=ch.get("band", ""),
        utilization_pct=float(ch.get("utilization", ch.get("cu_total", 0))),
        interference_pct=float(ch.get("interference", ch.get("cu_self_rx", 0))),
        num_bss=int(ch.get("num_bss", 0)),
    )


def get_rf_environment(mac: str | None = None) -> list[RfChannel]:
    """
    Get RF channel environment / utilisation stats.

    If mac is provided, returns data for that AP only.
    Otherwise returns aggregated data from all APs.

    Uses neighbouring AP data as a proxy for RF environment when
    per-channel stats are not available directly.

    Endpoint: GET /proxy/network/api/s/{site}/stat/spectrumscan/{mac}
              or falls back to rogue AP data aggregated by channel
    """
    if mac:
        mac = validate_mac_address(mac, "AP MAC")
    rate_limiter.check("rf")

    site = _resolve_site_name()

    # Try spectrum scan endpoint first
    if mac:
        try:
            data = _session.get_json(f"{_classic_path(site)}/stat/spectrumscan/{mac}")
            if isinstance(data, dict):
                items = data.get("data", [])
                if items:
                    channels = [_parse_rf_channel(ch) for ch in items]
                    audit_log("get_rf_environment", details={"mac": mac, "count": len(channels)})
                    return channels
        except Exception:
            pass  # Fall back to rogue AP aggregation

    # Fallback: aggregate from rogue AP data
    rogues = list_rogue_aps()
    ch_map: dict[tuple[int, str], dict] = {}
    for r in rogues:
        key = (r.channel, r.band)
        if key not in ch_map:
            ch_map[key] = {"channel": r.channel, "band": r.band, "num_bss": 0}
        ch_map[key]["num_bss"] += 1

    channels = [
        RfChannel(
            channel=v["channel"],
            band=v["band"],
            utilization_pct=0.0,  # not available from rogue data
            interference_pct=0.0,
            num_bss=v["num_bss"],
        )
        for v in sorted(ch_map.values(), key=lambda x: (x["band"], x["channel"]))
    ]

    audit_log("get_rf_environment", details={"mac": mac, "count": len(channels)})
    return channels


# ---------------------------------------------------------------------------
# Classic API: Combined Security Overview
# ---------------------------------------------------------------------------


def get_security_overview() -> dict:
    """
    Get a combined security overview for the AI assistant.

    Combines IPS events, rogue APs, alarms, and blocked clients
    into a single actionable summary.
    """
    rate_limiter.check("read")

    ips = list_ips_events(limit=50)
    rogues = list_rogue_aps()
    alarms = list_alarms(limit=50)
    clients = list_active_clients()

    blocked_clients = [c for c in clients if c.blocked]

    # Categorise IPS by severity
    ips_by_action: dict[str, int] = {}
    for event in ips:
        a = event.action or "unknown"
        ips_by_action[a] = ips_by_action.get(a, 0) + 1

    # Recent unhandled alarms
    unhandled_alarms = [a for a in alarms if not a.archived and not a.handled]

    issues: list[str] = []
    if ips:
        issues.append(f"{len(ips)} IPS event(s) detected (last 50)")
    if rogues:
        actual_rogues = [r for r in rogues if r.is_rogue]
        if actual_rogues:
            issues.append(f"{len(actual_rogues)} rogue AP(s) detected")
    if unhandled_alarms:
        issues.append(f"{len(unhandled_alarms)} unhandled alarm(s)")
    if blocked_clients:
        issues.append(
            f"{len(blocked_clients)} blocked client(s): "
            + ", ".join(c.hostname or c.mac for c in blocked_clients[:5])
        )

    overview = {
        "ips_events": {
            "total": len(ips),
            "by_action": ips_by_action,
            "recent": [
                {
                    "msg": e.msg,
                    "src_ip": e.src_ip,
                    "dst_ip": e.dst_ip,
                    "action": e.action,
                    "catname": e.catname,
                    "timestamp": e.timestamp,
                }
                for e in ips[:10]
            ],
        },
        "rogue_aps": {
            "total": len(rogues),
            "rogue_count": sum(1 for r in rogues if r.is_rogue),
            "neighbor_count": sum(1 for r in rogues if not r.is_rogue),
            "recent": [
                {
                    "bssid": r.bssid,
                    "essid": r.essid,
                    "channel": r.channel,
                    "rssi": r.rssi,
                    "is_rogue": r.is_rogue,
                }
                for r in rogues[:10]
            ],
        },
        "alarms": {
            "total": len(alarms),
            "unhandled": len(unhandled_alarms),
            "recent_unhandled": [
                {"msg": a.msg, "datetime": a.datetime, "key": a.key} for a in unhandled_alarms[:10]
            ],
        },
        "blocked_clients": {
            "count": len(blocked_clients),
            "list": [{"mac": c.mac, "hostname": c.hostname, "ip": c.ip} for c in blocked_clients],
        },
        "issues": issues,
        "all_ok": len(issues) == 0,
    }

    audit_log("get_security_overview")
    return overview
