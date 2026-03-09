"""
Tests for Childermass Network MCP client – classic API functions.

Covers:
- Data class parsing helpers
- Public functions with mocked HTTP session
- Input validation integration (MAC, period, limits)
- Error paths

Run with:
    pytest src/childermass/network_mcp/tests/test_client.py -v
"""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from childermass.network_mcp.client import (
    ActiveClient,
    Alarm,
    DeviceInfo,
    DpiStat,
    Event,
    HealthStatus,
    IpsEvent,
    RfChannel,
    RogueAp,
    SiteStats,
    _parse_alarm,
    _parse_client,
    _parse_device,
    _parse_dpi,
    _parse_event,
    _parse_health,
    _parse_ips_event,
    _parse_rf_channel,
    _parse_rogue_ap,
    _parse_site_stat,
    archive_alarm,
    block_client,
    get_client_details,
    get_client_dpi,
    get_client_history,
    get_device_details,
    get_dpi_stats,
    get_rf_environment,
    get_security_overview,
    get_site_health,
    get_site_stats,
    list_active_clients,
    list_alarms,
    list_devices,
    list_events,
    list_ips_events,
    list_rogue_aps,
    reconnect_client,
    restart_device,
    unblock_client,
)
from childermass.network_mcp.security import SecurityError

# =========================================================================
# Constants / sample payloads
# =========================================================================

SAMPLE_MAC = "aa:bb:cc:dd:ee:ff"
DEVICE_MAC = "11:22:33:44:55:66"

HEALTH_PAYLOAD = {
    "data": [
        {
            "subsystem": "www",
            "status": "ok",
            "latency": 5,
            "xput_down": 100.0,
            "xput_up": 20.0,
        },
        {
            "subsystem": "wan",
            "status": "ok",
            "wan_ip": "1.2.3.4",
            "num_gw": 1,
            "isp_name": "TestISP",
            "gw_system_stats": {"uptime": 86400, "cpu": 12.5, "mem": 45.0},
        },
        {
            "subsystem": "lan",
            "status": "ok",
            "lan_ip": "192.168.1.1",
            "num_sw": 2,
        },
        {
            "subsystem": "wlan",
            "status": "ok",
            "num_ap": 3,
            "num_adopted": 3,
            "num_disconnected": 0,
            "num_pending": 0,
        },
    ]
}

CLIENT_PAYLOAD = {
    "mac": SAMPLE_MAC,
    "hostname": "laptop",
    "ip": "192.168.1.42",
    "network": "LAN",
    "is_wired": True,
    "rx_bytes": 1000,
    "tx_bytes": 2000,
    "uptime": 3600,
    "last_seen": 1700000000,
    "oui": "TestMfg",
    "blocked": False,
    "noted": False,
    "name": "My Laptop",
}

DEVICE_PAYLOAD = {
    "mac": DEVICE_MAC,
    "model": "U6-LR",
    "name": "Living Room AP",
    "type": "uap",
    "adopted": True,
    "state": 1,
    "ip": "192.168.1.10",
    "version": "6.5.28",
    "uptime": 604800,
    "last_seen": 1700000000,
    "satisfaction": 98,
    "num_sta": 12,
    "system-stats": {"cpu": "5.0", "mem": "30.0"},
}

DPI_PAYLOAD = {
    "cat": 3,
    "app": 42,
    "rx_bytes": 500000,
    "tx_bytes": 100000,
    "rx_packets": 1000,
    "tx_packets": 200,
}

IPS_PAYLOAD = {
    "timestamp": 1700000000000,
    "key": "IPS:drop:1",
    "msg": "ET SCAN Suspicious inbound",
    "src_ip": "10.0.0.1",
    "dst_ip": "192.168.1.1",
    "src_port": 12345,
    "dst_port": 443,
    "proto": "tcp",
    "catname": "Attempted Information Leak",
    "action": "drop",
    "in_iface": "eth0",
    "archived": False,
}

ROGUE_PAYLOAD = {
    "bssid": "ff:ee:dd:cc:bb:aa",
    "essid": "EvilTwin",
    "channel": 6,
    "rssi": -55,
    "security": "wpa2",
    "oui": "Unknown",
    "band": "2.4GHz",
    "age": 120,
    "last_seen": 1700000000,
    "ap_mac": DEVICE_MAC,
    "is_rogue": True,
}

ALARM_PAYLOAD = {
    "_id": "alarm-001",
    "key": "EVT_AP_Disconnected",
    "msg": "AP disconnected",
    "datetime": "2025-01-15T10:00:00Z",
    "archived": False,
    "handled": False,
}

EVENT_PAYLOAD = {
    "_id": "evt-001",
    "key": "EVT_WU_Connected",
    "msg": "User connected",
    "datetime": "2025-01-15T10:00:00Z",
    "subsystem": "wlan",
}

RF_PAYLOAD = {
    "channel": 6,
    "band": "2.4GHz",
    "utilization": 45.0,
    "interference": 10.0,
    "num_bss": 8,
}


# =========================================================================
# Fixtures
# =========================================================================


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Reset rate limiter buckets before each test."""
    from childermass.network_mcp.security import rate_limiter

    rate_limiter._buckets.clear()


@pytest.fixture()
def mock_session():
    """Patch the module-level _session and _resolve_site_name."""
    session = MagicMock()
    with (
        patch("childermass.network_mcp.client._session", session),
        patch("childermass.network_mcp.client._resolve_site_name", return_value="default"),
        patch("childermass.network_mcp.client.audit_log"),
    ):
        yield session


def _json_response(payload, status_code: int = 200) -> MagicMock:
    """Create a mock httpx.Response returning *payload* as JSON."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp


# =========================================================================
# Parser unit tests (no HTTP needed)
# =========================================================================


class TestParseHealth:
    def test_basic(self):
        h = _parse_health(HEALTH_PAYLOAD["data"])
        assert isinstance(h, HealthStatus)
        assert h.status == "ok"
        assert h.num_ap == 3
        assert h.num_gw == 1
        assert h.wan_ip == "1.2.3.4"
        assert h.isp_name == "TestISP"
        assert h.download_speed_mbps == 100.0
        assert h.upload_speed_mbps == 20.0
        assert "www" in h.subsystems

    def test_empty(self):
        h = _parse_health([])
        assert h.status == "unknown"
        assert h.num_ap == 0


class TestParseClient:
    def test_wired(self):
        c = _parse_client(CLIENT_PAYLOAD)
        assert isinstance(c, ActiveClient)
        assert c.mac == SAMPLE_MAC
        assert c.hostname == "laptop"
        assert c.is_wired is True
        assert c.signal is None  # wired → no signal

    def test_wireless(self):
        payload = {**CLIENT_PAYLOAD, "is_wired": False, "signal": -55}
        c = _parse_client(payload)
        assert c.is_wired is False
        assert c.signal == -55

    def test_defaults(self):
        c = _parse_client({})
        assert c.mac == ""
        assert c.blocked is False


class TestParseDevice:
    def test_basic(self):
        d = _parse_device(DEVICE_PAYLOAD)
        assert isinstance(d, DeviceInfo)
        assert d.mac == DEVICE_MAC
        assert d.name == "Living Room AP"
        assert d.type == "uap"
        assert d.num_clients == 12
        assert d.cpu_used_pct == 5.0

    def test_defaults(self):
        d = _parse_device({})
        assert d.adopted is False
        assert d.state == 0


class TestParseDpi:
    def test_basic(self):
        d = _parse_dpi(DPI_PAYLOAD)
        assert isinstance(d, DpiStat)
        assert d.cat == 3
        assert d.app == 42
        assert d.rx_bytes == 500000


class TestParseIpsEvent:
    def test_basic(self):
        e = _parse_ips_event(IPS_PAYLOAD)
        assert isinstance(e, IpsEvent)
        assert e.action == "drop"
        assert e.src_ip == "10.0.0.1"

    def test_defaults(self):
        e = _parse_ips_event({})
        assert e.msg == ""
        assert e.archived is False


class TestParseRogueAp:
    def test_basic(self):
        r = _parse_rogue_ap(ROGUE_PAYLOAD)
        assert isinstance(r, RogueAp)
        assert r.essid == "EvilTwin"
        assert r.is_rogue is True


class TestParseAlarm:
    def test_basic(self):
        a = _parse_alarm(ALARM_PAYLOAD)
        assert isinstance(a, Alarm)
        assert a.id == "alarm-001"
        assert a.archived is False

    def test_handled_via_admin_id(self):
        payload = {**ALARM_PAYLOAD, "handled_admin_id": "admin1"}
        del payload["handled"]  # remove explicit handled so fallback logic applies
        a = _parse_alarm(payload)
        assert a.handled is True


class TestParseEvent:
    def test_basic(self):
        e = _parse_event(EVENT_PAYLOAD)
        assert isinstance(e, Event)
        assert e.subsystem == "wlan"


class TestParseRfChannel:
    def test_basic(self):
        ch = _parse_rf_channel(RF_PAYLOAD)
        assert isinstance(ch, RfChannel)
        assert ch.channel == 6
        assert ch.utilization_pct == 45.0

    def test_alt_keys(self):
        ch = _parse_rf_channel({"channel": 36, "band": "5GHz", "cu_total": 30.0})
        assert ch.utilization_pct == 30.0


class TestParseSiteStat:
    def test_basic(self):
        s = _parse_site_stat(
            {
                "time": 1700000000,
                "wan-rx_bytes": 5000,
                "wan-tx_bytes": 3000,
                "num_sta": 10,
                "lan-num_sta": 4,
                "wlan-num_sta": 6,
            }
        )
        assert isinstance(s, SiteStats)
        assert s.wan_rx_bytes == 5000
        assert s.num_sta == 10


# =========================================================================
# Public function tests (mocked session)
# =========================================================================


class TestGetSiteHealth:
    def test_success(self, mock_session):
        mock_session.get_json.return_value = HEALTH_PAYLOAD
        h = get_site_health()
        assert isinstance(h, HealthStatus)
        assert h.status == "ok"

    def test_list_response(self, mock_session):
        """Some firmware returns a list directly."""
        mock_session.get_json.return_value = HEALTH_PAYLOAD["data"]
        h = get_site_health()
        assert h.status == "ok"


class TestListActiveClients:
    def test_success(self, mock_session):
        mock_session.get_json.return_value = {"data": [CLIENT_PAYLOAD]}
        clients = list_active_clients()
        assert len(clients) == 1
        assert clients[0].mac == SAMPLE_MAC

    def test_empty(self, mock_session):
        mock_session.get_json.return_value = {"data": []}
        assert list_active_clients() == []


class TestGetClientDetails:
    def test_success(self, mock_session):
        mock_session.get_json.return_value = {"data": [CLIENT_PAYLOAD]}
        c = get_client_details(SAMPLE_MAC)
        assert c.mac == SAMPLE_MAC

    def test_not_found(self, mock_session):
        mock_session.get_json.return_value = {"data": []}
        with pytest.raises(RuntimeError, match="not found"):
            get_client_details(SAMPLE_MAC)

    def test_invalid_mac(self, mock_session):
        with pytest.raises(SecurityError, match="Invalid"):
            get_client_details("not-a-mac")


class TestGetClientHistory:
    def test_success(self, mock_session):
        resp = _json_response({"data": [{"rx_bytes": 100, "tx_bytes": 200, "time": 1700000000}]})
        mock_session.post.return_value = resp
        history = get_client_history(SAMPLE_MAC, hours=24)
        assert len(history) == 1

    def test_invalid_hours(self, mock_session):
        with pytest.raises(SecurityError):
            get_client_history(SAMPLE_MAC, hours=0)


class TestBlockClient:
    def test_success(self, mock_session):
        resp = _json_response({"data": []})
        mock_session.post.return_value = resp
        assert block_client(SAMPLE_MAC) is True

    def test_invalid_mac(self, mock_session):
        with pytest.raises(SecurityError, match="Invalid"):
            block_client("bad")


class TestUnblockClient:
    def test_success(self, mock_session):
        resp = _json_response({"data": []})
        mock_session.post.return_value = resp
        assert unblock_client(SAMPLE_MAC) is True


class TestReconnectClient:
    def test_success(self, mock_session):
        resp = _json_response({"data": []})
        mock_session.post.return_value = resp
        assert reconnect_client(SAMPLE_MAC) is True


class TestListDevices:
    def test_success(self, mock_session):
        mock_session.get_json.return_value = {"data": [DEVICE_PAYLOAD]}
        devices = list_devices()
        assert len(devices) == 1
        assert devices[0].name == "Living Room AP"

    def test_empty(self, mock_session):
        mock_session.get_json.return_value = {"data": []}
        assert list_devices() == []


class TestGetDeviceDetails:
    def test_success(self, mock_session):
        mock_session.get_json.return_value = {"data": [DEVICE_PAYLOAD]}
        d = get_device_details(DEVICE_MAC)
        assert d.mac == DEVICE_MAC

    def test_not_found(self, mock_session):
        mock_session.get_json.return_value = {"data": []}
        with pytest.raises(RuntimeError, match="not found"):
            get_device_details(DEVICE_MAC)


class TestRestartDevice:
    def test_success(self, mock_session):
        resp = _json_response({"data": []})
        mock_session.post.return_value = resp
        assert restart_device(DEVICE_MAC) is True


class TestGetSiteStats:
    def test_success(self, mock_session):
        resp = _json_response(
            {
                "data": [
                    {
                        "time": 1700000000,
                        "wan-rx_bytes": 5000,
                        "wan-tx_bytes": 3000,
                        "num_sta": 10,
                        "lan-num_sta": 4,
                        "wlan-num_sta": 6,
                    }
                ]
            }
        )
        mock_session.post.return_value = resp
        stats = get_site_stats(period="hourly")
        assert len(stats) == 1
        assert stats[0].wan_rx_bytes == 5000

    def test_invalid_period(self, mock_session):
        with pytest.raises(SecurityError, match="Invalid period"):
            get_site_stats(period="weekly")


class TestGetDpiStats:
    def test_success(self, mock_session):
        mock_session.get_json.return_value = {"data": [DPI_PAYLOAD]}
        stats = get_dpi_stats("by_app")
        assert len(stats) == 1
        assert stats[0].cat == 3

    def test_invalid_type(self, mock_session):
        with pytest.raises(SecurityError, match="Invalid dpi_type"):
            get_dpi_stats("by_user")


class TestGetClientDpi:
    def test_success(self, mock_session):
        resp = _json_response({"data": [DPI_PAYLOAD]})
        mock_session.post.return_value = resp
        stats = get_client_dpi(SAMPLE_MAC)
        assert len(stats) == 1


class TestListIpsEvents:
    def test_success(self, mock_session):
        mock_session.get_json.return_value = {"data": [IPS_PAYLOAD]}
        events = list_ips_events(limit=10)
        assert len(events) == 1
        assert events[0].action == "drop"

    def test_invalid_limit(self, mock_session):
        with pytest.raises(SecurityError):
            list_ips_events(limit=0)


class TestListRogueAps:
    def test_success(self, mock_session):
        mock_session.get_json.return_value = {"data": [ROGUE_PAYLOAD]}
        aps = list_rogue_aps()
        assert len(aps) == 1
        assert aps[0].is_rogue is True

    def test_empty(self, mock_session):
        mock_session.get_json.return_value = {"data": []}
        assert list_rogue_aps() == []


class TestListAlarms:
    def test_success(self, mock_session):
        mock_session.get_json.return_value = {"data": [ALARM_PAYLOAD]}
        alarms = list_alarms(limit=10)
        assert len(alarms) == 1
        assert alarms[0].id == "alarm-001"

    def test_archived(self, mock_session):
        mock_session.get_json.return_value = {"data": []}
        alarms = list_alarms(limit=10, archived=True)
        assert alarms == []


class TestArchiveAlarm:
    def test_success(self, mock_session):
        resp = _json_response({"data": []})
        mock_session.post.return_value = resp
        assert archive_alarm("alarm-001") is True

    def test_empty_id(self, mock_session):
        with pytest.raises(SecurityError, match="required"):
            archive_alarm("")


class TestListEvents:
    def test_success(self, mock_session):
        mock_session.get_json.return_value = {"data": [EVENT_PAYLOAD]}
        events = list_events(limit=10)
        assert len(events) == 1
        assert events[0].subsystem == "wlan"


class TestGetRfEnvironment:
    def test_with_spectrum_data(self, mock_session):
        mock_session.get_json.return_value = {"data": [RF_PAYLOAD]}
        channels = get_rf_environment(mac=DEVICE_MAC)
        assert len(channels) == 1
        assert channels[0].channel == 6

    def test_fallback_to_rogue_aggregation(self, mock_session):
        """When spectrum scan fails, falls back to rogue AP aggregation."""
        # First call (spectrum) raises exception
        mock_session.get_json.side_effect = [
            Exception("not supported"),
            {"data": [ROGUE_PAYLOAD]},  # list_rogue_aps call
        ]
        channels = get_rf_environment(mac=DEVICE_MAC)
        assert len(channels) >= 1

    def test_no_mac(self, mock_session):
        """Without a MAC, goes straight to rogue AP aggregation."""
        mock_session.get_json.return_value = {"data": [ROGUE_PAYLOAD]}
        channels = get_rf_environment()
        assert len(channels) >= 1


class TestGetSecurityOverview:
    def test_all_clear(self, mock_session):
        mock_session.get_json.return_value = {"data": []}
        overview = get_security_overview()
        assert overview["all_ok"] is True
        assert overview["ips_events"]["total"] == 0
        assert overview["rogue_aps"]["total"] == 0

    def test_with_issues(self, mock_session):
        # Respond differently per URL
        def side_effect(url, **kwargs):
            if "ips/event" in url:
                return {"data": [IPS_PAYLOAD]}
            if "rogueap" in url:
                return {"data": [ROGUE_PAYLOAD]}
            if "alarm" in url:
                return {"data": [ALARM_PAYLOAD]}
            if "stat/sta" in url:
                blocked = {**CLIENT_PAYLOAD, "blocked": True}
                return {"data": [blocked]}
            return {"data": []}

        mock_session.get_json.side_effect = side_effect
        overview = get_security_overview()
        assert overview["all_ok"] is False
        assert overview["ips_events"]["total"] == 1
        assert overview["rogue_aps"]["rogue_count"] == 1
        assert overview["alarms"]["unhandled"] == 1
        assert overview["blocked_clients"]["count"] == 1
        assert len(overview["issues"]) >= 1
