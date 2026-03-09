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
# Health / System tools (Classic API)
# ---------------------------------------------------------------------------


@mcp.tool()
def network_get_site_health() -> dict:
    """
    Get overall site health status.

    Returns subsystem statuses (www, wan, lan, wlan), device counts,
    WAN IP, ISP info, speed test results, and gateway resource usage.
    Ideal for daily health checks and proactive issue detection.

    Returns:
        Health summary with subsystem statuses, device counts, and metrics
    """
    try:
        health = client.get_site_health()
        return asdict(health)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Client tools (Classic API)
# ---------------------------------------------------------------------------


@mcp.tool()
def network_list_active_clients() -> list[dict] | dict:
    """
    List all clients currently connected to the network.

    Returns MAC, hostname, IP, network name, wired/wireless, traffic,
    signal strength (Wi-Fi), and manufacturer for each client.
    Useful for monitoring who is on the network and detecting unknown devices.

    Returns:
        List of active clients with connection details
    """
    try:
        clients = client.list_active_clients()
        return [asdict(c) for c in clients]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_get_client_details(mac: str) -> dict:
    """
    Get detailed information for a specific client by MAC address.

    Args:
        mac: Client MAC address (aa:bb:cc:dd:ee:ff format)

    Returns:
        Client details including traffic, signal, hostname, blocked status
    """
    try:
        c = client.get_client_details(mac=mac)
        return asdict(c)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_get_client_history(
    mac: str,
    hours: int = 24,
) -> list[dict] | dict:
    """
    Get traffic history for a specific client (hourly buckets).

    Useful for detecting unusual bandwidth usage or activity patterns.

    Args:
        mac: Client MAC address (aa:bb:cc:dd:ee:ff format)
        hours: Hours of history to fetch (default 24, max 8760)

    Returns:
        List of hourly traffic buckets with rx/tx bytes
    """
    try:
        return client.get_client_history(mac=mac, hours=hours)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_block_client(mac: str) -> dict:
    """
    Block a client from the network by MAC address.

    ⚠️ Action: The client will be immediately disconnected and prevented
    from reconnecting. Use for security incidents (unknown device, breach).

    Args:
        mac: Client MAC address to block (aa:bb:cc:dd:ee:ff format)

    Returns:
        Confirmation of block action
    """
    try:
        client.block_client(mac=mac)
        return {"blocked": True, "mac": mac}
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_unblock_client(mac: str) -> dict:
    """
    Unblock a previously blocked client.

    Args:
        mac: Client MAC address to unblock (aa:bb:cc:dd:ee:ff format)

    Returns:
        Confirmation of unblock action
    """
    try:
        client.unblock_client(mac=mac)
        return {"unblocked": True, "mac": mac}
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_reconnect_client(mac: str) -> dict:
    """
    Force-reconnect (kick) a wireless client.

    The client will be disconnected and must reassociate. Useful for
    fixing connectivity issues without blocking the device.

    Args:
        mac: Client MAC address to reconnect (aa:bb:cc:dd:ee:ff format)

    Returns:
        Confirmation of reconnect action
    """
    try:
        client.reconnect_client(mac=mac)
        return {"reconnected": True, "mac": mac}
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Device tools (Classic API)
# ---------------------------------------------------------------------------


@mcp.tool()
def network_list_devices() -> list[dict] | dict:
    """
    List all adopted UniFi network devices (access points, switches, gateways).

    Returns model, name, type, firmware version, uptime, client count,
    CPU/memory usage, and adoption state for each device.
    Useful for monitoring device health and detecting offline equipment.

    Returns:
        List of devices with status and resource metrics
    """
    try:
        devices = client.list_devices()
        return [asdict(d) for d in devices]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_get_device_details(mac: str) -> dict:
    """
    Get detailed information for a specific UniFi device by MAC.

    Args:
        mac: Device MAC address (aa:bb:cc:dd:ee:ff format)

    Returns:
        Device details including model, firmware, uptime, clients, CPU/memory
    """
    try:
        d = client.get_device_details(mac=mac)
        return asdict(d)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_restart_device(mac: str) -> dict:
    """
    Restart (reboot) a UniFi network device.

    ⚠️ Action: The device will go offline for 1-3 minutes during reboot.
    Connected clients will be temporarily disconnected.

    Args:
        mac: Device MAC address to restart (aa:bb:cc:dd:ee:ff format)

    Returns:
        Confirmation of restart command
    """
    try:
        client.restart_device(mac=mac)
        return {"restarted": True, "mac": mac}
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Traffic statistics tools (Classic API)
# ---------------------------------------------------------------------------


@mcp.tool()
def network_get_site_stats(
    period: str = "hourly",
) -> list[dict] | dict:
    """
    Get aggregated site traffic statistics (WAN rx/tx, client counts).

    Returns time-series data bucketed by period for the last 24 hours.
    Useful for detecting traffic anomalies and bandwidth trends.

    Args:
        period: Aggregation period – "hourly", "daily", or "5minutes"

    Returns:
        List of time-bucketed traffic statistics
    """
    try:
        stats = client.get_site_stats(period=period)
        return [asdict(s) for s in stats]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# DPI tools (Classic API)
# ---------------------------------------------------------------------------


@mcp.tool()
def network_get_dpi_stats(dpi_type: str = "by_app") -> list[dict] | dict:
    """
    Get Deep Packet Inspection traffic statistics.

    Shows which applications and categories are consuming bandwidth.
    Useful for detecting unexpected traffic patterns (e.g., torrent, VPN tunnels).

    Args:
        dpi_type: Aggregation – "by_app" (per application) or "by_cat" (per category)

    Returns:
        List of DPI entries with category, app, and traffic bytes/packets
    """
    try:
        stats = client.get_dpi_stats(dpi_type=dpi_type)
        return [asdict(s) for s in stats]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_get_client_dpi(mac: str) -> list[dict] | dict:
    """
    Get DPI (application usage) stats for a specific client.

    Shows which apps/categories a particular device is using.
    Useful for investigating suspicious client behaviour.

    Args:
        mac: Client MAC address (aa:bb:cc:dd:ee:ff format)

    Returns:
        List of DPI entries for the client with app, category, bytes
    """
    try:
        stats = client.get_client_dpi(mac=mac)
        return [asdict(s) for s in stats]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Security tools (Classic API)
# ---------------------------------------------------------------------------


@mcp.tool()
def network_list_ips_events(limit: int = 100) -> list[dict] | dict:
    """
    List recent Intrusion Prevention System (IPS) events.

    Shows detected threats, blocked connections, and security alerts.
    Critical for security monitoring – review regularly for breach indicators.

    Args:
        limit: Max events to return (default 100, max 10000)

    Returns:
        List of IPS events with source/dest IPs, threat category, action
    """
    try:
        events = client.list_ips_events(limit=limit)
        return [asdict(e) for e in events]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_list_rogue_aps() -> list[dict] | dict:
    """
    List detected rogue and neighboring access points.

    Detects unauthorized APs that could be evil twins or signal interference.
    Critical for wireless security monitoring.

    Returns:
        List of rogue/neighboring APs with BSSID, SSID, channel, signal strength
    """
    try:
        rogues = client.list_rogue_aps()
        return [asdict(r) for r in rogues]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_list_alarms(
    limit: int = 100,
    archived: bool = False,
) -> list[dict] | dict:
    """
    List system alarms (security alerts, device issues, connectivity problems).

    Shows controller-generated alerts about device failures, security events,
    and network issues. Review unhandled alarms for actionable items.

    Args:
        limit: Max alarms to return (default 100, max 10000)
        archived: Include already-handled/archived alarms (default: False)

    Returns:
        List of alarms with message, datetime, archive/handled status
    """
    try:
        alarms = client.list_alarms(limit=limit, archived=archived)
        return [asdict(a) for a in alarms]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_archive_alarm(alarm_id: str) -> dict:
    """
    Archive (acknowledge) an alarm.

    Marks an alarm as handled so it no longer appears in unhandled lists.

    Args:
        alarm_id: Alarm ID to archive

    Returns:
        Confirmation of archive action
    """
    try:
        client.archive_alarm(alarm_id=alarm_id)
        return {"archived": True, "alarm_id": alarm_id}
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_list_events(limit: int = 100) -> list[dict] | dict:
    """
    List recent controller events (device connections, client activity, etc.).

    General event log useful for troubleshooting and activity auditing.
    Distinct from IPS events – these cover device, WLAN, and system events.

    Args:
        limit: Max events to return (default 100, max 10000)

    Returns:
        List of events with type, message, datetime, and subsystem
    """
    try:
        events = client.list_events(limit=limit)
        return [asdict(e) for e in events]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def network_get_security_overview() -> dict:
    """
    Get a comprehensive security overview for the home network.

    Combines IPS events, rogue APs, alarms, and blocked clients into
    a single actionable summary. This is the primary tool for the AI
    assistant's security monitoring workflow.

    Returns:
        Security overview with IPS summary, rogue APs, unhandled alarms,
        blocked clients, and issue list
    """
    try:
        return client.get_security_overview()
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# WiFi / RF tools (Classic API)
# ---------------------------------------------------------------------------


@mcp.tool()
def network_get_rf_environment(mac: str = "") -> list[dict] | dict:
    """
    Get RF (radio frequency) channel environment and utilisation.

    Shows channel congestion, neighbouring BSS count, and interference.
    Useful for diagnosing Wi-Fi performance issues and optimising channels.

    Args:
        mac: Optional AP MAC to get data for a specific AP (empty = all APs)

    Returns:
        List of RF channels with utilisation, interference, and BSS counts
    """
    try:
        channels = client.get_rf_environment(mac=mac or None)
        return [asdict(ch) for ch in channels]
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
