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
import urllib3
from dataclasses import dataclass

import httpx

from .auth import get_console_url, get_credentials, get_site_id, load_config, verify_ssl
from .security import (
    SecurityError,
    audit_log,
    rate_limiter,
    validate_filter_expression,
    validate_max_results,
    validate_network_id,
    validate_network_name,
    validate_offset,
    validate_policy_action,
    validate_policy_id,
    validate_policy_name,
    validate_site_id,
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
                raise RuntimeError(
                    "Console not configured. Run setup first:\n"
                    "  python -m childermass.network_mcp.auth --setup"
                )

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
            raise RuntimeError(
                "Cannot connect to console. Check that it is reachable."
            )

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
            raise SecurityError(
                "Console authentication failed – invalid username or password"
            )
        elif login_resp.status_code != 200:
            raise RuntimeError(
                f"Console login failed with HTTP {login_resp.status_code}"
            )

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

    raise SecurityError(
        "site_id is required. Either pass it explicitly or configure "
        "a default via: python -m childermass.network_mcp.auth --setup"
    )


# ---------------------------------------------------------------------------
# Application Info
# ---------------------------------------------------------------------------


def get_app_info() -> NetworkInfo:
    """Get application version information."""
    rate_limiter.check("info")

    data = _session.get_json(f"{_API_PREFIX}/info")
    if not isinstance(data, dict):
        raise RuntimeError("Unexpected info response format")

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
        raise RuntimeError("Unexpected networks response format")

    networks = [_parse_network(n) for n in data.get("data", [])]

    audit_log("list_networks", details={
        "site_id": sid,
        "count": len(networks),
    })

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
        raise RuntimeError("Unexpected network response format")

    network = _parse_network(data)

    audit_log("get_network", details={
        "site_id": sid,
        "network_id": network_id,
        "name": network.name,
    })

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

    audit_log("get_network_references", details={
        "site_id": sid,
        "network_id": network_id,
    })

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

    audit_log("create_network", details={
        "site_id": sid,
        "name": name,
        "vlan_id": vlan_id,
        "network_id": network.id,
    })

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
        raise RuntimeError("Unexpected network response format")

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

    audit_log("update_network", details={
        "site_id": sid,
        "network_id": network_id,
        "updates": {
            k: v for k, v in {
                "name": name, "vlan_id": vlan_id, "enabled": enabled
            }.items() if v is not None
        },
    })

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

    audit_log("delete_network", details={
        "site_id": sid,
        "network_id": network_id,
        "force": force,
    })

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
        raise RuntimeError("Unexpected firewall policies response format")

    policies = [_parse_policy(p) for p in data.get("data", [])]

    audit_log("list_firewall_policies", details={
        "site_id": sid,
        "count": len(policies),
    })

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
        raise RuntimeError("Unexpected policy response format")

    policy = _parse_policy(data)

    audit_log("get_firewall_policy", details={
        "site_id": sid,
        "policy_id": policy_id,
        "name": policy.name,
    })

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

    audit_log("create_firewall_policy", details={
        "site_id": sid,
        "name": name,
        "action": action,
        "policy_id": policy.id,
    })

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
        raise RuntimeError("Unexpected policy response format")

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

    audit_log("update_firewall_policy", details={
        "site_id": sid,
        "policy_id": policy_id,
        "updates": {
            k: v for k, v in {
                "name": name, "enabled": enabled,
                "action": action, "logging": logging_enabled,
            }.items() if v is not None
        },
    })

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

    audit_log("delete_firewall_policy", details={
        "site_id": sid,
        "policy_id": policy_id,
    })

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
        raise RuntimeError("Unexpected ordering response format")

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

    audit_log("set_policy_ordering", details={
        "site_id": sid,
        "count": len(validated_ids),
    })

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
        raise RuntimeError("Unexpected zones response format")

    zones = [_parse_zone(z) for z in data.get("data", [])]

    audit_log("list_firewall_zones", details={
        "site_id": sid,
        "count": len(zones),
    })

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
        raise RuntimeError("Unexpected zone response format")

    zone = _parse_zone(data)

    audit_log("get_firewall_zone", details={
        "site_id": sid,
        "zone_id": zone_id,
        "name": zone.name,
    })

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

    audit_log("create_firewall_zone", details={
        "site_id": sid,
        "name": name,
        "zone_id": zone.id,
    })

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

    audit_log("update_firewall_zone", details={
        "site_id": sid,
        "zone_id": zone_id,
        "name": name,
    })

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

    audit_log("delete_firewall_zone", details={
        "site_id": sid,
        "zone_id": zone_id,
    })

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
        raise RuntimeError("Unexpected vouchers response format")

    vouchers = [_parse_voucher(v) for v in data.get("data", [])]

    audit_log("list_vouchers", details={
        "site_id": sid,
        "count": len(vouchers),
    })

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
        raise RuntimeError("Unexpected voucher response format")

    voucher = _parse_voucher(data)

    audit_log("get_voucher", details={
        "site_id": sid,
        "voucher_id": voucher_id,
    })

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

    audit_log("generate_vouchers", details={
        "site_id": sid,
        "count": len(vouchers),
        "name": name,
    })

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

    audit_log("delete_voucher", details={
        "site_id": sid,
        "voucher_id": voucher_id,
    })

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

    audit_log("delete_vouchers_bulk", details={
        "site_id": sid,
        "filter": filter_expr,
    })

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
