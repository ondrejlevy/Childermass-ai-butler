"""
Childermass UniFi Network MCP Server

Custom UniFi Network MCP server for Claude Code / OpenCode.
All communication is local – direct HTTPS to the console on the LAN.

Security: All tool responses go through error sanitization so that
console credentials, IP addresses, or cookies are never leaked to the LLM.

Run with: python -m childermass.network_mcp.server
"""

from dataclasses import asdict

from mcp.server.fastmcp import FastMCP

from . import client
from .security import SecurityError, sanitize_error_message


# Create FastMCP server
mcp = FastMCP("childermass-network")


# ---------------------------------------------------------------------------
# Helper: safe tool wrapper
# ---------------------------------------------------------------------------


def _safe_call(func, *args, **kwargs):
    """Execute a client call with error sanitization."""
    try:
        return func(*args, **kwargs)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# System tools
# ---------------------------------------------------------------------------


@mcp.tool()
def network_get_info() -> dict:
    """
    Get UniFi Network application version information.

    Returns:
        Dict with application version
    """
    try:
        info = client.get_app_info()
        return asdict(info)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_get_status(site_id: str = "") -> dict:
    """
    Get comprehensive UniFi Network status overview.

    Returns a combined summary of networks, firewall policies, firewall zones,
    and vouchers for a quick health check. Ideal for daily briefings.

    Args:
        site_id: Site UUID (uses default from config if empty)

    Returns:
        Combined status with app version, networks, firewall, vouchers, and issues
    """
    try:
        return client.get_network_status(
            site_id=site_id or None,
        )
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Network tools
# ---------------------------------------------------------------------------


@mcp.tool()
def network_list_networks(
    site_id: str = "",
    limit: int = 50,
    offset: int = 0,
) -> list[dict] | dict:
    """
    List all networks configured on the UniFi site.

    Returns network name, VLAN ID, enabled status, DHCP guarding info.

    Args:
        site_id: Site UUID (uses default from config if empty)
        limit: Max results (default 50, max 200)
        offset: Pagination offset

    Returns:
        List of networks with id, name, vlan_id, enabled, management type
    """
    try:
        networks = client.list_networks(
            site_id=site_id or None,
            limit=limit,
            offset=offset,
        )
        return [asdict(n) for n in networks]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_get_network(
    network_id: str,
    site_id: str = "",
) -> dict:
    """
    Get details for a specific network.

    Use network_list_networks first to get network IDs.

    Args:
        network_id: Network UUID (from network_list_networks)
        site_id: Site UUID (uses default from config if empty)

    Returns:
        Network details including name, VLAN, enabled status, DHCP guarding
    """
    try:
        network = client.get_network(
            network_id=network_id,
            site_id=site_id or None,
        )
        return asdict(network)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_create_network(
    name: str,
    site_id: str = "",
    vlan_id: int = 0,
    enabled: bool = True,
) -> dict:
    """
    Create a new network (e.g. guest WiFi, IoT VLAN).

    Args:
        name: Network name (e.g. "Guest WiFi", "IoT Devices")
        site_id: Site UUID (uses default from config if empty)
        vlan_id: VLAN ID (1-4094, 0 = untagged/no VLAN)
        enabled: Whether the network is enabled (default: True)

    Returns:
        Created network details
    """
    try:
        network = client.create_network(
            name=name,
            site_id=site_id or None,
            vlan_id=vlan_id if vlan_id > 0 else None,
            enabled=enabled,
        )
        return asdict(network)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_update_network(
    network_id: str,
    site_id: str = "",
    name: str = "",
    vlan_id: int = -1,
    enabled: str = "",
) -> dict:
    """
    Update an existing network configuration.

    Only provided (non-empty) fields are updated.

    Args:
        network_id: Network UUID (from network_list_networks)
        site_id: Site UUID (uses default from config if empty)
        name: New network name (empty = no change)
        vlan_id: New VLAN ID, 1-4094 (-1 = no change)
        enabled: "true" or "false" (empty = no change)

    Returns:
        Updated network details
    """
    try:
        network = client.update_network(
            network_id=network_id,
            site_id=site_id or None,
            name=name or None,
            vlan_id=vlan_id if vlan_id >= 0 else None,
            enabled={"true": True, "false": False}.get(enabled.lower()) if enabled else None,
        )
        return asdict(network)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_delete_network(
    network_id: str,
    site_id: str = "",
    force: bool = False,
) -> dict:
    """
    Delete a network.

    ⚠️ Destructive operation – use with caution.

    Args:
        network_id: Network UUID (from network_list_networks)
        site_id: Site UUID (uses default from config if empty)
        force: Force deletion even if network has active references

    Returns:
        Confirmation of deletion
    """
    try:
        client.delete_network(
            network_id=network_id,
            site_id=site_id or None,
            force=force,
        )
        return {"deleted": True, "network_id": network_id}
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Firewall tools
# ---------------------------------------------------------------------------


@mcp.tool()
def network_list_firewall_policies(
    site_id: str = "",
    limit: int = 50,
    offset: int = 0,
) -> list[dict] | dict:
    """
    List all firewall policies on the UniFi site.

    Returns policy name, action (ALLOW/DROP/REJECT), source/destination zones,
    enabled status, and ordering index.

    Args:
        site_id: Site UUID (uses default from config if empty)
        limit: Max results (default 50, max 200)
        offset: Pagination offset

    Returns:
        List of firewall policies
    """
    try:
        policies = client.list_firewall_policies(
            site_id=site_id or None,
            limit=limit,
            offset=offset,
        )
        return [asdict(p) for p in policies]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_get_firewall_policy(
    policy_id: str,
    site_id: str = "",
) -> dict:
    """
    Get details for a specific firewall policy.

    Args:
        policy_id: Policy UUID (from network_list_firewall_policies)
        site_id: Site UUID (uses default from config if empty)

    Returns:
        Policy details including action, zones, IP version, logging, schedule
    """
    try:
        policy = client.get_firewall_policy(
            policy_id=policy_id,
            site_id=site_id or None,
        )
        return asdict(policy)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_create_firewall_policy(
    name: str,
    action: str,
    source_zone_id: str,
    destination_zone_id: str,
    site_id: str = "",
    enabled: bool = True,
    description: str = "",
    ip_version: str = "BOTH",
    logging_enabled: bool = False,
) -> dict:
    """
    Create a new firewall policy rule.

    Use network_list_firewall_zones to get zone IDs.

    Args:
        name: Policy name (e.g. "Block IoT to LAN")
        action: Action type – "ALLOW", "DROP", or "REJECT"
        source_zone_id: Source zone UUID (from network_list_firewall_zones)
        destination_zone_id: Destination zone UUID
        site_id: Site UUID (uses default from config if empty)
        enabled: Whether the policy is active (default: True)
        description: Optional policy description
        ip_version: IP version scope – "IPv4", "IPv6", or "BOTH" (default)
        logging_enabled: Whether to log rule matches (default: False)

    Returns:
        Created policy details
    """
    try:
        policy = client.create_firewall_policy(
            name=name,
            action=action,
            source_zone_id=source_zone_id,
            destination_zone_id=destination_zone_id,
            site_id=site_id or None,
            enabled=enabled,
            description=description,
            ip_version=ip_version,
            logging_enabled=logging_enabled,
        )
        return asdict(policy)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_update_firewall_policy(
    policy_id: str,
    site_id: str = "",
    name: str = "",
    enabled: str = "",
    description: str = "",
    action: str = "",
    logging_enabled: str = "",
) -> dict:
    """
    Update an existing firewall policy.

    Only provided (non-empty) fields are updated.

    Args:
        policy_id: Policy UUID (from network_list_firewall_policies)
        site_id: Site UUID (uses default from config if empty)
        name: New policy name (empty = no change)
        enabled: "true" or "false" (empty = no change)
        description: New description (empty = no change)
        action: New action – "ALLOW", "DROP", or "REJECT" (empty = no change)
        logging_enabled: "true" or "false" (empty = no change)

    Returns:
        Updated policy details
    """
    try:
        policy = client.update_firewall_policy(
            policy_id=policy_id,
            site_id=site_id or None,
            name=name or None,
            enabled={"true": True, "false": False}.get(enabled.lower()) if enabled else None,
            description=description or None,
            action=action or None,
            logging_enabled=(
                {"true": True, "false": False}.get(logging_enabled.lower())
                if logging_enabled
                else None
            ),
        )
        return asdict(policy)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_delete_firewall_policy(
    policy_id: str,
    site_id: str = "",
) -> dict:
    """
    Delete a firewall policy.

    ⚠️ Destructive operation – use with caution.

    Args:
        policy_id: Policy UUID (from network_list_firewall_policies)
        site_id: Site UUID (uses default from config if empty)

    Returns:
        Confirmation of deletion
    """
    try:
        client.delete_firewall_policy(
            policy_id=policy_id,
            site_id=site_id or None,
        )
        return {"deleted": True, "policy_id": policy_id}
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_list_firewall_zones(
    site_id: str = "",
) -> list[dict] | dict:
    """
    List all firewall zones on the UniFi site.

    Zones are used as source/destination in firewall policies.
    Common zones: Internal, External, DMZ, VPN, Guest.

    Args:
        site_id: Site UUID (uses default from config if empty)

    Returns:
        List of firewall zones with id and name
    """
    try:
        zones = client.list_firewall_zones(
            site_id=site_id or None,
        )
        return [asdict(z) for z in zones]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Voucher tools
# ---------------------------------------------------------------------------


@mcp.tool()
def network_list_vouchers(
    site_id: str = "",
    limit: int = 50,
    offset: int = 0,
) -> list[dict] | dict:
    """
    List hotspot vouchers on the UniFi site.

    Shows voucher codes, usage, expiration, and limits.

    Args:
        site_id: Site UUID (uses default from config if empty)
        limit: Max results (default 50, max 200)
        offset: Pagination offset

    Returns:
        List of vouchers with code, expiration, limits, and usage info
    """
    try:
        vouchers = client.list_vouchers(
            site_id=site_id or None,
            limit=limit,
            offset=offset,
        )
        return [asdict(v) for v in vouchers]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_get_voucher(
    voucher_id: str,
    site_id: str = "",
) -> dict:
    """
    Get details for a specific voucher.

    Args:
        voucher_id: Voucher UUID (from network_list_vouchers)
        site_id: Site UUID (uses default from config if empty)

    Returns:
        Voucher details with code, limits, usage, and expiration
    """
    try:
        voucher = client.get_voucher(
            voucher_id=voucher_id,
            site_id=site_id or None,
        )
        return asdict(voucher)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_generate_vouchers(
    site_id: str = "",
    name: str = "",
    count: int = 1,
    time_limit_minutes: int = 0,
    data_limit_mb: int = 0,
    download_limit_kbps: int = 0,
    upload_limit_kbps: int = 0,
    guest_limit: int = 0,
) -> list[dict] | dict:
    """
    Generate new hotspot vouchers for guest network access.

    Creates one or more voucher codes that guests can use to authenticate
    to the hotspot/captive portal.

    Args:
        site_id: Site UUID (uses default from config if empty)
        name: Optional voucher name/label
        count: Number of vouchers to generate (default 1, max 1000)
        time_limit_minutes: Time limit in minutes (0 = no limit, max ~525600 = 1 year)
        data_limit_mb: Data usage limit in MB (0 = no limit)
        download_limit_kbps: Download speed limit in kbps (0 = no limit)
        upload_limit_kbps: Upload speed limit in kbps (0 = no limit)
        guest_limit: Max simultaneous guests per voucher (0 = no limit)

    Returns:
        List of generated vouchers with codes
    """
    try:
        vouchers = client.generate_vouchers(
            site_id=site_id or None,
            name=name or None,
            count=count,
            time_limit_minutes=time_limit_minutes if time_limit_minutes > 0 else None,
            data_limit_mb=data_limit_mb if data_limit_mb > 0 else None,
            download_limit_kbps=download_limit_kbps if download_limit_kbps > 0 else None,
            upload_limit_kbps=upload_limit_kbps if upload_limit_kbps > 0 else None,
            guest_limit=guest_limit if guest_limit > 0 else None,
        )
        return [asdict(v) for v in vouchers]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_delete_voucher(
    voucher_id: str,
    site_id: str = "",
) -> dict:
    """
    Delete a hotspot voucher.

    Args:
        voucher_id: Voucher UUID (from network_list_vouchers)
        site_id: Site UUID (uses default from config if empty)

    Returns:
        Confirmation of deletion
    """
    try:
        client.delete_voucher(
            voucher_id=voucher_id,
            site_id=site_id or None,
        )
        return {"deleted": True, "voucher_id": voucher_id}
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Server entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
