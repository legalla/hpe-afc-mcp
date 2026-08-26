"""MCP server skeleton for Aruba Fabric Composer."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
from collections import Counter
from typing import Any

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

import afc_auth
from afc_client import AFCClient

load_dotenv()

logging.basicConfig(level=os.environ.get("AFC_LOG_LEVEL", "INFO").upper())
logger = logging.getLogger("afc-mcp")

_host = os.environ.get("MCP_HOST", "0.0.0.0")
_port = int(os.environ.get("MCP_PORT", "8000"))

mcp = FastMCP("afc-mcp", host=_host, port=_port)


# ── Security: optional Bearer authentication ──────────────────────────
# Disabled by default (backward compatible). Enable via AFC_AUTH_ENABLED=true
# (typically in docker-compose.yml) once at least one token has been created
# with `afc_token_manager.py generate --name <client>`.


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


_AUTH_ENABLED = _env_bool("AFC_AUTH_ENABLED", False)
_TOKENS_FILE = os.environ.get("AFC_TOKENS_FILE", afc_auth.DEFAULT_TOKENS_FILE)
_MCP_PATH = os.environ.get("AFC_MCP_PATH", "/mcp")
_TRUST_FORWARDED = _env_bool("AFC_TRUST_FORWARDED_FOR", False)

# Built lazily at startup (see __main__).
_token_store: "afc_auth.TokenStore | None" = None


def _init_security() -> None:
    """Build the token store and enforce startup rules.

    Policy: if Bearer auth is enabled but no token exists yet, the server still
    starts but in LOCKED mode — every MCP request is refused (HTTP 503) until a
    token is created. This lets an operator generate the first token without
    first disabling authentication; a restart then activates it.
    """
    global _token_store

    if not _AUTH_ENABLED:
        logger.warning(
            "🔓 Bearer authentication is DISABLED (AFC_AUTH_ENABLED not set). "
            "The MCP endpoint is open to any client that can reach it."
        )
        return

    _token_store = afc_auth.TokenStore(_TOKENS_FILE)
    if len(_token_store) == 0:
        logger.warning(
            "🔒 AFC_AUTH_ENABLED=true but no token found in '%s'. Starting in "
            "LOCKED mode: all MCP requests are refused (HTTP 503) until a token "
            "exists. Create the first one with: docker compose exec afc-mcp "
            "python afc_token_manager.py generate --name <client> — then RESTART "
            "the container.",
            _TOKENS_FILE,
        )
    else:
        logger.info(
            "🔒 Bearer authentication ENABLED — %d token(s) loaded from %s",
            len(_token_store), _TOKENS_FILE,
        )

_afc_client: AFCClient | None = None


def _client() -> AFCClient:
    global _afc_client
    if _afc_client is None:
        base_url = os.environ.get("AFC_BASE_URL", "").strip()
        username = os.environ.get("AFC_USERNAME", "").strip()
        password = os.environ.get("AFC_PASSWORD", "").strip()
        verify_ssl = os.environ.get("AFC_VERIFY_SSL", "false").lower() == "true"
        timeout = int(os.environ.get("AFC_TIMEOUT", "30"))
        _afc_client = AFCClient(
            base_url=base_url,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )
    return _afc_client


def _items_from_response(payload: dict[str, Any]) -> list[dict[str, Any]]:
    result = payload.get("result")
    if isinstance(result, list):
        return [item for item in result if isinstance(item, dict)]
    if isinstance(result, dict):
        return [result]
    return []


def _status_breakdown(items: list[dict[str, Any]], status_key: str, fallback_key: str | None = None) -> dict[str, int]:
    values: list[str] = []
    for item in items:
        value = item.get(status_key)
        if value is None and fallback_key:
            value = item.get(fallback_key)
        values.append(str(value) if value is not None else "unknown")
    return dict(Counter(values))


_HEALTHY_STATES = {"healthy", "healthy_but", "up", "ok"}
_WARNING_STATES = {"unknown", "healthy_but", "minor", "degraded", "upgrading"}
_CRITICAL_STATES = {"major", "critical", "non_recoverable", "down"}


def _worst_status(states: list[str]) -> str:
    """Return the most severe status found in a list of health/severity values."""
    normalized = [str(state).lower() for state in states]
    if any(state in _CRITICAL_STATES for state in normalized):
        return "critical"
    if any(state in _WARNING_STATES or state not in _HEALTHY_STATES for state in normalized):
        return "degraded"
    return "healthy"


def _unhealthy_items(items: list[dict[str, Any]], status_key: str, fallback_key: str | None = None) -> list[dict[str, Any]]:
    """Return items whose health/status is not in a healthy state."""
    unhealthy: list[dict[str, Any]] = []
    for item in items:
        value = item.get(status_key)
        if value is None and fallback_key:
            value = item.get(fallback_key)
        if value is None:
            continue
        if str(value).lower() not in _HEALTHY_STATES:
            unhealthy.append(item)
    return unhealthy


def _bgp_down_neighbors(vrf_uuid: str | None, vrf_name: str | None, bgp_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract BGP neighbors that are administratively up but not Established."""
    down: list[dict[str, Any]] = []
    result = bgp_data.get("result", bgp_data)
    switches = result.get("switches", []) if isinstance(result, dict) else []
    for switch in switches:
        if not isinstance(switch, dict):
            continue
        switch_uuid = switch.get("uuid")
        for neighbor in switch.get("neighbors", []) or []:
            if not isinstance(neighbor, dict):
                continue
            admin_status = str(neighbor.get("admin_status", "up")).lower()
            state = str(neighbor.get("state", "")).lower()
            if admin_status == "down":
                continue  # administratively disabled, not a fault
            if state != "established":
                down.append(
                    {
                        "vrf_uuid": vrf_uuid,
                        "vrf_name": vrf_name,
                        "switch_uuid": switch_uuid,
                        "neighbor": neighbor.get("neighbor"),
                        "remote_as": neighbor.get("remote_as"),
                        "state": neighbor.get("state"),
                        "admin_status": neighbor.get("admin_status"),
                    }
                )
    return down


def _ospf_down_neighbors(vrf_uuid: str | None, vrf_name: str | None, ospf_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract OSPF neighbor entries whose health is not in a healthy state."""
    down: list[dict[str, Any]] = []
    for item in _items_from_response(ospf_data):
        health = item.get("health")
        status = health.get("status") if isinstance(health, dict) else health
        status = str(status if status is not None else "unknown").lower()
        if status in _HEALTHY_STATES:
            continue
        down.append(
            {
                "vrf_uuid": vrf_uuid,
                "vrf_name": vrf_name,
                "switch_uuid": item.get("switch_uuid"),
                "interface_name": item.get("interface_name"),
                "ospf_router_name": item.get("ospf_router_name"),
                "area_id": item.get("area_id"),
                "health": status,
            }
        )
    return down


def _looks_like_uuid(value: str) -> bool:
    """Heuristic: AFC UUIDs are 32 hex chars, optionally hyphenated (36)."""
    v = value.strip().replace("-", "")
    return len(v) == 32 and all(c in "0123456789abcdefABCDEF" for c in v)


def _find_switch(switch: str) -> dict[str, Any] | None:
    """Return the switch record matching a UUID or a name, if any."""
    switches = _items_from_response(_client().list_switches())
    if _looks_like_uuid(switch):
        return next((s for s in switches if s.get("uuid") == switch), None)
    return next((s for s in switches if str(s.get("name", "")).lower() == switch.lower()), None)


def _resolve_switch_uuid(switch: str) -> str:
    """Return a switch UUID from a UUID (passthrough) or a switch name (looked up)."""
    if _looks_like_uuid(switch):
        return switch
    record = _find_switch(switch)
    if record and record.get("uuid"):
        return record["uuid"]
    raise ValueError(f"No switch named '{switch}' was found.")


def _resolve_fabric_uuid(fabric: str) -> str:
    """Return a fabric UUID from a UUID (passthrough) or a fabric name (looked up)."""
    if _looks_like_uuid(fabric):
        return fabric
    fabrics = _items_from_response(_client().list_fabrics(include_switches=False))
    match = next((f for f in fabrics if str(f.get("name", "")).lower() == fabric.lower()), None)
    if match and match.get("uuid"):
        return match["uuid"]
    raise ValueError(f"No fabric named '{fabric}' was found.")


def _switch_port_maps() -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    """Build switch_uuid->name and port_uuid->{switch_name,switch_port} maps (best-effort)."""
    switch_names: dict[str, str] = {}
    port_to_switch: dict[str, dict[str, Any]] = {}
    try:
        for sw in _items_from_response(_client().list_switches(include_ports=True)):
            sw_uuid = sw.get("uuid")
            if sw_uuid:
                switch_names[sw_uuid] = sw.get("name")
            for port in sw.get("ports") or []:
                if port.get("uuid"):
                    port_to_switch[port["uuid"]] = {
                        "switch_uuid": sw_uuid,
                        "switch_name": sw.get("name"),
                        "switch_port": port.get("name"),
                    }
    except Exception:  # noqa: BLE001 - name resolution is best-effort
        return {}, {}
    return switch_names, port_to_switch


def _enrich_subleaf_object(
    obj: dict[str, Any],
    switch_names: dict[str, str],
    port_to_switch: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Add resolved switch names/ports and device:port endpoints to a subleaf object.

    Leaves UUIDs untouched and adds sibling `switch_name` (per peer / per LAG
    member) plus `switch_ports` and an `endpoints` list (``switch:port``) so the
    LAG members and upstream devices are identifiable without extra lookups.
    """
    # The list endpoint returns `subleaf_leaf_peers` as a list; the single-peer
    # endpoint returns the parent object with it as one dict. Normalize to a list.
    peers = obj.get("subleaf_leaf_peers")
    if isinstance(peers, dict):
        peers = [peers]
    for group in peers or []:
        if not isinstance(group, dict):
            continue
        for peer in group.get("peers") or []:
            peer_sw = peer.get("switch_uuid")
            if peer_sw:
                peer["switch_name"] = switch_names.get(peer_sw)
            lag = peer.get("subleaf_leaf_lag")
            if not isinstance(lag, dict):
                continue
            endpoints: list[str] = []
            for pp in lag.get("port_properties") or []:
                pp_sw = pp.get("switch_uuid")
                pp["switch_name"] = switch_names.get(pp_sw)
                ports: list[str] = []
                for port_uuid in pp.get("port_uuids") or []:
                    info = port_to_switch.get(port_uuid)
                    ports.append(info["switch_port"] if info else port_uuid)
                pp["switch_ports"] = ports
                label = switch_names.get(pp_sw) or pp_sw
                endpoints.extend(f"{label}:{port}" for port in ports)
            lag["endpoints"] = endpoints
    return obj



def _resolve_vrf_uuid(vrf: str, fabric_uuid: str | None = None) -> str:
    """Return a VRF UUID from a UUID (passthrough) or a VRF name.

    VRF names are not globally unique (one instance per fabric). When several
    VRFs share the name, `fabric_uuid` (typically that of the target switch) is
    used to pick the right instance; ambiguity without a hint raises an error
    listing the candidates.
    """
    if _looks_like_uuid(vrf):
        return vrf
    matches = [
        item
        for item in _items_from_response(
            _client().list_vrfs(include_bgp=False, include_ospf=False, include_networks=False)
        )
        if str(item.get("name", "")).lower() == vrf.lower()
    ]
    if not matches:
        raise ValueError(f"No VRF named '{vrf}' was found.")
    if fabric_uuid:
        scoped = [m for m in matches if m.get("fabric_uuid") == fabric_uuid]
        if scoped:
            matches = scoped
    if len(matches) == 1:
        uuid = matches[0].get("uuid")
        if uuid:
            return uuid
    candidates = ", ".join(f"{m.get('uuid')} (fabric {m.get('fabric_uuid')})" for m in matches)
    raise ValueError(
        f"VRF name '{vrf}' is ambiguous ({len(matches)} instances). Pass a switch "
        f"to scope it to its fabric, or use a VRF UUID. Candidates: {candidates}"
    )



def _format_prefix(prefix: Any) -> str | None:
    """Render an AFC prefix as ``a.b.c.d/len``.

    The live API returns the prefix as a ready-made CIDR string; the OpenAPI
    schema documents it as an object ``{address, prefix_length}``. Accept both.
    """
    if isinstance(prefix, str):
        return prefix or None
    if isinstance(prefix, dict):
        address = prefix.get("address")
        length = prefix.get("prefix_length")
        if address is None or length is None:
            return None
        return f"{address}/{length}"
    return None


def _normalize_next_hops(next_hop_info: Any) -> list[dict[str, Any]]:
    """Normalize ``next_hop_info`` (a string like 'blackhole' or a list) into a list."""
    if isinstance(next_hop_info, str):
        return [{"next_hop": None, "interface": None, "type": next_hop_info}]
    if isinstance(next_hop_info, list):
        hops: list[dict[str, Any]] = []
        for hop in next_hop_info:
            if isinstance(hop, dict):
                hops.append({"next_hop": hop.get("next_hop"), "interface": hop.get("interface")})
        return hops
    return []


def _simplify_route(route: dict[str, Any]) -> dict[str, Any]:
    """Reduce a raw AFC route entry to the routing-decision essentials."""
    return {
        "prefix": _format_prefix(route.get("prefix")),
        "next_hops": _normalize_next_hops(route.get("next_hop_info")),
        "protocol": route.get("protocol"),
        "sub_protocol_type": route.get("sub_protocol_type"),
        "route_type": route.get("route_type"),
        "distance": route.get("distance"),
        "metric": route.get("metric"),
        "address_family": route.get("address_family"),
        "switch_name": route.get("switch_name"),
        "switch_uuid": route.get("switch_uuid"),
    }


def _simplify_static_route(route: dict[str, Any]) -> dict[str, Any]:
    """Reduce a raw AFC static-route entry to its configuration essentials.

    ``next_hop`` is null for a nullroute (discard) entry; ``0.0.0.0`` means the
    route follows the default route. ``switch_uuids`` is empty for fabric-scoped
    routes.
    """
    return {
        "name": route.get("name"),
        "destination": _format_prefix(route.get("destination")),
        "next_hop": route.get("next_hop"),
        "nexthop_interface_name": route.get("nexthop_interface_name"),
        "type": route.get("type"),
        "distance": route.get("distance"),
        "tag": route.get("tag"),
        "switch_uuids": route.get("switch_uuids"),
        "description": route.get("description"),
        "uuid": route.get("uuid"),
    }


def _longest_prefix_match(routes: list[dict[str, Any]], destination: str) -> list[dict[str, Any]]:
    """Return the most specific route(s) covering *destination* (an IP or CIDR).

    Mirrors the forwarding decision: among routes whose prefix contains the
    destination, keep those with the longest prefix length. An exact prefix
    match wins outright. Returns all routes sharing the best length (e.g. the
    same prefix installed on several switches or as ECMP).
    """
    try:
        query_net = ipaddress.ip_network(destination, strict=False)
    except ValueError:
        return []

    best_len = -1
    winners: list[dict[str, Any]] = []
    for route in routes:
        prefix = route.get("prefix")
        if not prefix:
            continue
        try:
            route_net = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        if route_net.version != query_net.version:
            continue
        # The route covers the destination when the queried network is a subnet
        # of (or equal to) the route's prefix.
        if query_net.subnet_of(route_net):
            plen = route_net.prefixlen
            if plen > best_len:
                best_len = plen
                winners = [route]
            elif plen == best_len:
                winners.append(route)
    return winners



@mcp.tool()
def get_server_status() -> dict:
    """Return MCP status and AFC connection configuration (no secrets)."""
    info = _client().connection_info()
    return {
        "service": "afc-mcp",
        "status": "ready",
        "api_client": info,
        "capabilities": [
            "switch inventory and status",
            "fabric inventory",
            "vrf, bgp, ospf and evpn visibility",
            "vrf routing tables (ip route) and next-hop lookup",
            "vrf arp tables, ip interfaces and static routes",
            "virtual overlay and underlay details",
            "leaf-spine underlay/overlay and L2 leaf-spine configurations",
            "subleaf-leaf configurations",
            "vsx switch-pair (mlag) configurations",
            "ntp and dns client configurations",
        ],
    }



@mcp.tool()
def get_system_info() -> dict:
    """Return AFC system information."""
    return _client().get_system()


@mcp.tool()
def list_switches(
    include_ports: bool = False,
    include_software: bool = False,
    include_tags: bool = False,
    filter_query: str | None = None,
    page: int | None = None,
    page_size: int | None = None,
) -> dict:
    """List switches with optional details and status fields."""
    data = _client().list_switches(
        include_ports=include_ports,
        include_software=include_software,
        include_tags=include_tags,
        filter_query=filter_query,
        page=page,
        page_size=page_size,
    )
    items = _items_from_response(data)
    return {
        "count": data.get("count", len(items)),
        "status_by_health": _status_breakdown(items, "health", fallback_key="status"),
        "result": data.get("result", []),
        "page": data.get("page"),
    }


@mcp.tool()
def get_switch(switch_uuid: str, include_ports: bool = True, include_software: bool = True, include_tags: bool = True) -> dict:
    """Get one switch by UUID, including operational status fields."""
    return _client().get_switch(
        switch_uuid=switch_uuid,
        include_ports=include_ports,
        include_software=include_software,
        include_tags=include_tags,
    )


@mcp.tool()
def list_fabrics(
    include_switches: bool = True,
    filter_query: str | None = None,
    page: int | None = None,
    page_size: int | None = None,
) -> dict:
    """List fabrics with associated switches when requested."""
    data = _client().list_fabrics(
        include_switches=include_switches,
        filter_query=filter_query,
        page=page,
        page_size=page_size,
    )
    items = _items_from_response(data)
    return {
        "count": data.get("count", len(items)),
        "status_by_health": _status_breakdown(items, "health"),
        "result": data.get("result", []),
        "page": data.get("page"),
    }


@mcp.tool()
def get_fabric(fabric_uuid: str, include_switches: bool = True) -> dict:
    """Get one fabric and optionally its associated switches."""
    return _client().get_fabric(fabric_uuid=fabric_uuid, include_switches=include_switches)


@mcp.tool()
def list_vrfs(
    include_bgp: bool = True,
    include_ospf: bool = True,
    include_networks: bool = True,
    include_interfaces: bool = False,
    filter_query: str | None = None,
    page: int | None = None,
    page_size: int | None = None,
) -> dict:
    """List VRFs and include key routing context for each object."""
    return _client().list_vrfs(
        include_bgp=include_bgp,
        include_ospf=include_ospf,
        include_networks=include_networks,
        include_interfaces=include_interfaces,
        filter_query=filter_query,
        page=page,
        page_size=page_size,
    )


@mcp.tool()
def get_vrf(
    vrf_uuid: str,
    include_bgp: bool = True,
    include_ospf: bool = True,
    include_networks: bool = True,
    include_interfaces: bool = True,
) -> dict:
    """Get one VRF with BGP/OSPF/network/interface details."""
    return _client().get_vrf(
        vrf_uuid=vrf_uuid,
        include_bgp=include_bgp,
        include_ospf=include_ospf,
        include_networks=include_networks,
        include_interfaces=include_interfaces,
    )


@mcp.tool()
def get_vrf_switches(vrf: str, fabric: str | None = None, switch: str | None = None) -> dict:
    """List the switches on which a VRF is actually deployed.

    This answers "where is this VRF deployed?". `vrf` accepts a UUID or a name
    (e.g. `sense`). VRF names are NOT unique across fabrics (one instance per
    fabric), so pass `fabric` (name or UUID) or `switch` (name or UUID) to
    disambiguate and select the right instance; otherwise an ambiguous name
    raises an error listing the candidates. The result is read from the
    authoritative `/vrfs/{uuid}/switches` endpoint — an empty list means the VRF
    exists in configuration but is not applied to any switch.
    """
    fabric_uuid: str | None = None
    if switch:
        switch_record = _find_switch(switch)
        fabric_uuid = (switch_record or {}).get("fabric_uuid")
    if fabric_uuid is None and fabric:
        fabric_uuid = _resolve_fabric_uuid(fabric)
    vrf_uuid = _resolve_vrf_uuid(vrf, fabric_uuid=fabric_uuid)

    data = _client().list_vrf_switches(vrf_uuid=vrf_uuid)
    switches = _items_from_response(data)
    return {
        "vrf": vrf,
        "vrf_uuid": vrf_uuid,
        "fabric_uuid": fabric_uuid,
        "deployed": bool(switches),
        "count": data.get("count", len(switches)),
        "switches": switches,
    }


@mcp.tool()
def get_vrf_bgp_status(vrf_uuid: str, switch_uuid: str | None = None, include_neighbors: bool = True) -> dict:
    """Get BGP status for a VRF, globally or per switch."""
    return _client().get_vrf_bgp_status(
        vrf_uuid=vrf_uuid,
        switch_uuid=switch_uuid,
        include_neighbors=include_neighbors,
    )


@mcp.tool()
def get_vrf_bgp_summary(vrf_uuid: str, switch_uuid: str | None = None, include_neighbors: bool = True) -> dict:
    """Get BGP summary for a VRF, globally or per switch."""
    return _client().get_vrf_bgp_summary(
        vrf_uuid=vrf_uuid,
        switch_uuid=switch_uuid,
        include_neighbors=include_neighbors,
    )


@mcp.tool()
def get_vrf_ospf_neighbors(vrf_uuid: str, filter_query: str | None = None) -> dict:
    """Get OSPF neighbor status list for a VRF."""
    data = _client().get_vrf_ospf_neighbors(vrf_uuid=vrf_uuid, filter_query=filter_query)
    items = _items_from_response(data)
    return {
        "count": data.get("count", len(items)),
        "status_by_health": _status_breakdown(items, "health"),
        "result": data.get("result", []),
        "page": data.get("page"),
    }


@mcp.tool()
def get_vrf_ospf_summary(
    vrf_uuid: str,
    switch_uuid: str | None = None,
    ospf_router_uuid: str | None = None,
) -> dict:
    """Get OSPF summary for a VRF."""
    return _client().get_vrf_ospf_summary(
        vrf_uuid=vrf_uuid,
        switch_uuid=switch_uuid,
        ospf_router_uuid=ospf_router_uuid,
    )


@mcp.tool()
def get_vrf_routes(
    vrf: str,
    switch: str | None = None,
    destination: str | None = None,
    protocol: str | None = None,
    filter_query: str | None = None,
    page: int | None = None,
    page_size: int | None = None,
) -> dict:
    """Return the IP routing table (RIB) of a VRF, with optional next-hop lookup.

    `vrf` and `switch` accept either a UUID or a name (e.g. `mgmt`,
    `DC-8100-Leaf5`); names are resolved automatically. When `destination` is a
    host IP or CIDR, the tool performs a longest-prefix match and returns the
    winning route(s) and their next hop(s) — answering "what is the next hop
    toward X". `protocol` optionally filters by origin (bgp, ospf, static,
    connected, local, rip).
    """
    # Resolve the switch first so its fabric can disambiguate same-named VRFs.
    switch_record = _find_switch(switch) if switch else None
    switch_uuid = None
    if switch:
        switch_uuid = (switch_record or {}).get("uuid") or _resolve_switch_uuid(switch)
    fabric_uuid = (switch_record or {}).get("fabric_uuid")
    vrf_uuid = _resolve_vrf_uuid(vrf, fabric_uuid=fabric_uuid)
    switches = [switch_uuid] if switch_uuid else None

    data = _client().list_vrf_ip_routes(
        vrf_uuid=vrf_uuid,
        switches=switches,
        filter_query=filter_query,
        page=page,
        page_size=page_size,
    )
    routes = [_simplify_route(r) for r in _items_from_response(data)]

    if protocol:
        routes = [r for r in routes if str(r.get("protocol", "")).lower() == protocol.lower()]

    response: dict[str, Any] = {
        "vrf": vrf,
        "vrf_uuid": vrf_uuid,
        "switch": switch,
        "count": len(routes),
        "routes": routes,
        "page": data.get("page"),
    }

    if destination:
        best = _longest_prefix_match(routes, destination)
        response["destination"] = destination
        response["matched_routes"] = best
        response["next_hops"] = [hop for route in best for hop in route.get("next_hops", [])]
        response["count"] = len(best)
        # Keep the full table available but move it under a secondary key.
        response["routes"] = best
        response["all_routes"] = routes

    return response



@mcp.tool()
def get_vrf_arp(
    vrf: str,
    switch: str | None = None,
    filter_query: str | None = None,
    page: int | None = None,
    page_size: int | None = None,
) -> dict:
    """Return the ARP table of a VRF (IP-to-MAC bindings learned on switches).

    `vrf` and `switch` accept either a UUID or a name (e.g. `default`,
    `DC-8100-Leaf5`); names are resolved automatically. Pass `switch` to scope
    the table to one switch and to disambiguate same-named VRFs across fabrics.
    Each entry maps an IP address to a MAC address, the interface / physical
    port it was learned on, the owning switch and the neighbor reachability
    state (reachable, stale, incomplete, failed, permanent).
    """
    switch_record = _find_switch(switch) if switch else None
    switch_uuid = None
    if switch:
        switch_uuid = (switch_record or {}).get("uuid") or _resolve_switch_uuid(switch)
    fabric_uuid = (switch_record or {}).get("fabric_uuid")
    vrf_uuid = _resolve_vrf_uuid(vrf, fabric_uuid=fabric_uuid)
    switches = [switch_uuid] if switch_uuid else None

    data = _client().list_vrf_arp(
        vrf_uuid=vrf_uuid,
        switches=switches,
        filter_query=filter_query,
        page=page,
        page_size=page_size,
    )
    entries = _items_from_response(data)
    return {
        "vrf": vrf,
        "vrf_uuid": vrf_uuid,
        "switch": switch,
        "count": data.get("count", len(entries)),
        "arp_entries": entries,
        "page": data.get("page"),
    }



@mcp.tool()
def get_vrf_ip_interfaces(
    vrf: str,
    switch: str | None = None,
    if_type: str | None = None,
    include_status: bool = True,
    filter_query: str | None = None,
) -> dict:
    """Return the IP (L3) interfaces configured in a VRF.

    `vrf` and `switch` accept either a UUID or a name; names are resolved
    automatically (pass `switch` to disambiguate same-named VRFs across
    fabrics). `if_type` filters by interface kind: `routed`, `vlan`, `loopback`
    or `evpn`. When `include_status` is true, the operational state (admin
    up/down, MAC address, IP MTU, duplex, IPv4 address) is fetched from the
    interface status endpoint and returned under `status`, scoped to `switch`
    when provided.
    """
    switch_record = _find_switch(switch) if switch else None
    switch_uuid = None
    if switch:
        switch_uuid = (switch_record or {}).get("uuid") or _resolve_switch_uuid(switch)
    fabric_uuid = (switch_record or {}).get("fabric_uuid")
    vrf_uuid = _resolve_vrf_uuid(vrf, fabric_uuid=fabric_uuid)

    data = _client().list_vrf_ip_interfaces(
        vrf_uuid=vrf_uuid,
        if_type=if_type,
        filter_query=filter_query,
    )
    interfaces = _items_from_response(data)
    response: dict[str, Any] = {
        "vrf": vrf,
        "vrf_uuid": vrf_uuid,
        "switch": switch,
        "if_type": if_type,
        "count": data.get("count", len(interfaces)),
        "interfaces": data.get("result", interfaces),
        "page": data.get("page"),
    }
    if include_status:
        status = _client().get_vrf_ip_interfaces_status(
            vrf_uuid=vrf_uuid,
            switch_uuid=switch_uuid,
        )
        result = status.get("result", status)
        response["status"] = result.get("interfaces") if isinstance(result, dict) else result
    return response



@mcp.tool()
def get_vrf_static_routes(vrf: str, switch: str | None = None) -> dict:
    """Return the IP static routes configured in a VRF.

    `vrf` and `switch` accept either a UUID or a name; names are resolved
    automatically (pass `switch` to disambiguate same-named VRFs across
    fabrics). Each route exposes its destination prefix, next hop (an IP, or
    null for a nullroute / discard entry; `0.0.0.0` means follow the default
    route), optional next-hop interface, administrative distance, tag, type
    (`forward` / `nullroute`) and the switches it is applied to (empty for
    fabric-scoped routes). AFC has no dedicated static-route listing endpoint,
    so these are read from the VRF object.
    """
    switch_record = _find_switch(switch) if switch else None
    fabric_uuid = (switch_record or {}).get("fabric_uuid")
    vrf_uuid = _resolve_vrf_uuid(vrf, fabric_uuid=fabric_uuid)

    data = _client().get_vrf_static_routes(vrf_uuid=vrf_uuid)
    result = data.get("result", data)
    routes = result.get("ip_static_routes", []) if isinstance(result, dict) else []
    return {
        "vrf": vrf,
        "vrf_uuid": vrf_uuid,
        "switch": switch,
        "count": len(routes),
        "static_routes": [_simplify_static_route(r) for r in routes],
    }



@mcp.tool()
def list_evpn(
    fabrics: list[str] | None = None,
    switch_uuids: list[str] | None = None,
    filter_query: str | None = None,
    page: int | None = None,
    page_size: int | None = None,
) -> dict:
    """List EVPN objects and virtual network identifiers."""
    return _client().list_evpn(
        fabrics=fabrics,
        switch_uuids=switch_uuids,
        filter_query=filter_query,
        page=page,
        page_size=page_size,
    )


@mcp.tool()
def list_evpn_routes(
    switches: list[str] | None = None,
    filter_query: str | None = None,
    page: int | None = None,
    page_size: int | None = None,
) -> dict:
    """List EVPN route entries."""
    return _client().list_evpn_routes(
        switches=switches,
        filter_query=filter_query,
        page=page,
        page_size=page_size,
    )


@mcp.tool()
def get_vrf_virtual_environment(vrf_uuid: str, filter_query: str | None = None) -> dict:
    """Get virtual overlay and underlay information for a VRF."""
    overlay = _client().get_vrf_overlay(vrf_uuid=vrf_uuid, filter_query=filter_query)
    underlay = _client().get_vrf_underlay(vrf_uuid=vrf_uuid, filter_query=filter_query)
    return {
        "vrf_uuid": vrf_uuid,
        "overlay": overlay.get("result", overlay),
        "underlay": underlay.get("result", underlay),
    }


@mcp.tool()
def list_leaf_spine(
    fabric: str | None = None,
    include_interface: bool = False,
    filter_query: str | None = None,
    page: int | None = None,
    page_size: int | None = None,
) -> dict:
    """List Leaf-Spine peer configurations (the fabric underlay building blocks).

    Each object describes how leaves peer with spines (name, QoS trust and the
    per-switch leaf-spine peers). Pass `fabric` (name or UUID) to scope the query
    to one fabric; omit it to list Leaf-Spine objects across all fabrics. Set
    include_interface=True to expand the underlying leaf-spine interface details.
    """
    if fabric is not None:
        data = _client().list_fabric_leaf_spine(
            fabric_uuid=_resolve_fabric_uuid(fabric),
            include_interface=include_interface,
            filter_query=filter_query,
            page=page,
            page_size=page_size,
        )
    else:
        data = _client().list_leaf_spine(
            include_interface=include_interface,
            filter_query=filter_query,
            page=page,
            page_size=page_size,
        )
    items = _items_from_response(data)
    return {
        "count": data.get("count", len(items)),
        "result": data.get("result", []),
        "page": data.get("page"),
    }


@mcp.tool()
def get_leaf_spine(
    fabric: str,
    leaf_spine_uuid: str,
    include_interface: bool = False,
    filter_query: str | None = None,
) -> dict:
    """Get one Leaf-Spine peer configuration by UUID within a fabric.

    `fabric` accepts a fabric name or UUID; it is resolved automatically.
    """
    return _client().get_leaf_spine(
        fabric_uuid=_resolve_fabric_uuid(fabric),
        leaf_spine_uuid=leaf_spine_uuid,
        include_interface=include_interface,
        filter_query=filter_query,
    )


@mcp.tool()
def list_l2_leaf_spine(
    fabric: str | None = None,
    include_lag: bool = False,
    filter_query: str | None = None,
    page: int | None = None,
    page_size: int | None = None,
) -> dict:
    """List Layer-2 Leaf-Spine configurations across one or all fabrics.

    Pass `fabric` (name or UUID) to scope the query to a single fabric. Set
    include_lag=True to expand the LAG details of each L2 leaf-spine peer.
    """
    fabrics = [_resolve_fabric_uuid(fabric)] if fabric is not None else None
    data = _client().list_l2_leaf_spine(
        fabrics=fabrics,
        include_lag=include_lag,
        filter_query=filter_query,
        page=page,
        page_size=page_size,
    )
    items = _items_from_response(data)
    return {
        "count": data.get("count", len(items)),
        "result": data.get("result", []),
        "page": data.get("page"),
    }


@mcp.tool()
def list_vsx(
    fabric: str | None = None,
    include_isl_lag: bool = False,
    include_keep_alive_interface: bool = False,
    filter_query: str | None = None,
    page: int | None = None,
    page_size: int | None = None,
) -> dict:
    """List VSX pair configurations (the redundant switch pairing / MLAG layer).

    Each VSX pair exposes its name, system MAC, keep-alive VRF/UDP port, ISL/keep-alive
    timers, QoS trust, health and the two `vsx_peers` (primary/secondary switches). Pass
    `fabric` (name or UUID) to scope the query to one fabric, or omit it to list VSX pairs
    across all fabrics. Set include_isl_lag / include_keep_alive_interface to expand the
    Inter-Switch Link LAG and keep-alive interface details.
    """
    if fabric is not None:
        data = _client().list_fabric_vsx(
            fabric_uuid=_resolve_fabric_uuid(fabric),
            include_isl_lag=include_isl_lag,
            include_keep_alive_interface=include_keep_alive_interface,
            filter_query=filter_query,
            page=page,
            page_size=page_size,
        )
    else:
        data = _client().list_vsx(
            include_isl_lag=include_isl_lag,
            include_keep_alive_interface=include_keep_alive_interface,
            filter_query=filter_query,
            page=page,
            page_size=page_size,
        )
    items = _items_from_response(data)
    return {
        "count": data.get("count", len(items)),
        "result": data.get("result", []),
        "page": data.get("page"),
    }


@mcp.tool()
def get_vsx(
    fabric: str,
    vsx_uuid: str,
    include_isl_lag: bool = False,
    include_keep_alive_interface: bool = False,
    filter_query: str | None = None,
) -> dict:
    """Get one VSX pair configuration by UUID within a fabric.

    `fabric` accepts a fabric name or UUID; it is resolved automatically.
    """
    return _client().get_vsx(
        fabric_uuid=_resolve_fabric_uuid(fabric),
        vsx_uuid=vsx_uuid,
        include_isl_lag=include_isl_lag,
        include_keep_alive_interface=include_keep_alive_interface,
        filter_query=filter_query,
    )


@mcp.tool()
def list_subleaf_leaf(
    fabric: str | None = None,
    peer_uuid: str | None = None,
    include_lag: bool = True,
    resolve_switch_names: bool = True,
    filter_query: str | None = None,
    page: int | None = None,
    page_size: int | None = None,
) -> dict:
    """List Subleaf-Leaf configurations (subleaf switches attached below leaves).

    Each object exposes its name, type and `subleaf_leaf_peers` (the per-switch
    subleaf-leaf LAG bindings and status). Pass `fabric` (name or UUID) to scope
    the query to one fabric, or omit it to list across all fabrics.

    Pass `peer_uuid` to fetch a single subleaf-leaf peer by UUID instead of the
    full list; `fabric` is then required. `include_lag` (default True) expands the
    full subleaf-leaf LAG/LACP details of each peer; set it to False for a lighter
    response (peers and status only). `resolve_switch_names` (default True)
    enriches each peer/LAG member with the switch name, physical ports and
    `endpoints` (``switch:port``) so upstream devices are identifiable without
    extra lookups.
    """
    if peer_uuid is not None:
        if fabric is None:
            raise ValueError("`fabric` is required when `peer_uuid` is provided.")
        data = _client().get_subleaf_leaf_peer(
            fabric_uuid=_resolve_fabric_uuid(fabric),
            peer_uuid=peer_uuid,
            include_lag=include_lag,
            filter_query=filter_query,
        )
        obj = data.get("result", data)
        result = [obj] if isinstance(obj, dict) else []
    else:
        fabrics = [_resolve_fabric_uuid(fabric)] if fabric is not None else None
        data = _client().list_subleaf_leaf(
            fabrics=fabrics,
            include_lag=include_lag,
            filter_query=filter_query,
            page=page,
            page_size=page_size,
        )
        result = data.get("result", [])

    if resolve_switch_names and include_lag and result:
        switch_names, port_to_switch = _switch_port_maps()
        for obj in result:
            if isinstance(obj, dict):
                _enrich_subleaf_object(obj, switch_names, port_to_switch)

    return {
        "count": data.get("count", len(result)),
        "result": result,
        "page": data.get("page"),
    }


def _fabric_name_map() -> dict[str, str]:
    """Build a fabric_uuid -> fabric_name map (best-effort)."""
    try:
        fabrics = _items_from_response(_client().list_fabrics(include_switches=False))
    except Exception:  # noqa: BLE001 - name resolution is best-effort
        return {}
    return {f["uuid"]: f.get("name") for f in fabrics if f.get("uuid")}


@mcp.tool()
def list_multi_hop_vxlan(
    fabric: str | None = None,
    filter_query: str | None = None,
    page: int | None = None,
    page_size: int | None = None,
) -> dict:
    """List Multi-Fabric (Multi-Hop VXLAN) configurations that stitch fabrics together.

    Each object describes how one fabric's border leader peers with remote fabrics
    over L3 eBGP to extend VXLAN across sites: `name`, `fabric_uuid`/`fabric_name`
    (the local fabric), `border_leader`/`border_leader_name`, `l3_ebgp_borders` and
    `remote_fabrics` (each with site_name, fabric_name, remote border leader, ASN and
    BGP peer IPs). Pass `fabric` (name or UUID) to scope the query to one fabric, or
    omit it to list Multi-Hop VXLAN objects across all fabrics.
    """
    if fabric is not None:
        data = _client().list_fabric_multi_hop_vxlan(
            fabric_uuid=_resolve_fabric_uuid(fabric),
            filter_query=filter_query,
            page=page,
            page_size=page_size,
        )
    else:
        data = _client().list_multi_hop_vxlan(
            filter_query=filter_query,
            page=page,
            page_size=page_size,
        )
    result = data.get("result", [])
    if result:
        names = _fabric_name_map()
        for obj in result:
            if isinstance(obj, dict) and obj.get("fabric_uuid"):
                obj.setdefault("fabric_name", names.get(obj["fabric_uuid"]))
    return {
        "count": data.get("count", len(_items_from_response(data))),
        "result": result,
        "page": data.get("page"),
    }


@mcp.tool()
def get_multi_hop_vxlan(
    fabric: str,
    uuid: str,
    filter_query: str | None = None,
) -> dict:
    """Get one Multi-Fabric (Multi-Hop VXLAN) configuration by UUID within a fabric.

    `fabric` accepts a fabric name or UUID; it is resolved automatically.
    """
    data = _client().get_multi_hop_vxlan(
        fabric_uuid=_resolve_fabric_uuid(fabric),
        uuid=uuid,
        filter_query=filter_query,
    )
    obj = data.get("result", data)
    if isinstance(obj, dict) and obj.get("fabric_uuid"):
        obj.setdefault("fabric_name", _fabric_name_map().get(obj["fabric_uuid"]))
    return data


@mcp.tool()
def list_stretched_vlans(
    fabric: str | None = None,
    filter_query: str | None = None,
    page: int | None = None,
    page_size: int | None = None,
) -> dict:
    """List Stretched VLAN (EVPN Multi-Site) configurations spanning multiple fabrics.

    Each object exposes the `fabric_uuids` (and resolved `fabric_names`) the VLANs are
    stretched across, the `stretched_vlans` range (e.g. "5, 20-50, 70") and the
    `global_route_targets`. Pass `fabric` (name or UUID) to return only stretched-VLAN
    objects that include that fabric, or omit it to list across all fabrics.
    """
    fabrics = [_resolve_fabric_uuid(fabric)] if fabric is not None else None
    data = _client().list_evpn_multi_site(
        fabrics=fabrics,
        filter_query=filter_query,
        page=page,
        page_size=page_size,
    )
    result = data.get("result", [])
    if result:
        names = _fabric_name_map()
        for obj in result:
            if isinstance(obj, dict) and isinstance(obj.get("fabric_uuids"), list):
                obj.setdefault(
                    "fabric_names",
                    [names.get(u) for u in obj["fabric_uuids"]],
                )
    return {
        "count": data.get("count", len(_items_from_response(data))),
        "result": result,
        "page": data.get("page"),
    }


@mcp.tool()
def get_stretched_vlan(uuid: str, filter_query: str | None = None) -> dict:
    """Get one Stretched VLAN (EVPN Multi-Site) configuration by UUID.

    Returns the fabric_uuids (with resolved fabric_names), the stretched VLAN range
    and the global route targets for the object.
    """
    data = _client().get_evpn_multi_site(uuid=uuid, filter_query=filter_query)
    obj = data.get("result", data)
    if isinstance(obj, dict) and isinstance(obj.get("fabric_uuids"), list):
        names = _fabric_name_map()
        obj.setdefault("fabric_names", [names.get(u) for u in obj["fabric_uuids"]])
    return data


@mcp.tool()
def list_ntp_configurations(
    fabric: str | None = None,
    switch: str | None = None,
    in_use_only: bool = False,
    filter_query: str | None = None,
    page: int | None = None,
    page_size: int | None = None,
) -> dict:
    """List NTP client configurations and where they are applied.

    Each object exposes its NTP servers (entry_list) and the fabrics/switches it
    is applied to. `fabric` and `switch` accept a name or UUID and are resolved
    automatically to scope the query; set in_use_only=True to return only
    configurations currently applied to switches.
    """
    data = _client().list_ntp_configurations(
        fabric=_resolve_fabric_uuid(fabric) if fabric is not None else None,
        switch=_resolve_switch_uuid(switch) if switch is not None else None,
        in_use_only=in_use_only,
        filter_query=filter_query,
        page=page,
        page_size=page_size,
    )
    items = _items_from_response(data)
    return {
        "count": data.get("count", len(items)),
        "result": data.get("result", []),
        "page": data.get("page"),
    }


@mcp.tool()
def list_dns_configurations(
    fabric: str | None = None,
    switch: str | None = None,
    in_use_only: bool = False,
    filter_query: str | None = None,
    page: int | None = None,
    page_size: int | None = None,
) -> dict:
    """List DNS client configurations and where they are applied.

    Each object exposes its name servers, domain name/search list and the
    fabrics/switches it is applied to. `fabric` and `switch` accept a name or
    UUID and are resolved automatically to scope the query; set in_use_only=True
    to return only configurations currently applied to switches.
    """
    data = _client().list_dns_configurations(
        fabric=_resolve_fabric_uuid(fabric) if fabric is not None else None,
        switch=_resolve_switch_uuid(switch) if switch is not None else None,
        in_use_only=in_use_only,
        filter_query=filter_query,
        page=page,
        page_size=page_size,
    )
    items = _items_from_response(data)
    return {
        "count": data.get("count", len(items)),
        "result": data.get("result", []),
        "page": data.get("page"),
    }


@mcp.tool()
def list_afc_sites(filter_query: str | None = None) -> dict:
    """List AFC site integrations."""
    return _client().list_afc_sites(filter_query=filter_query)


@mcp.tool()
def get_afc_site_inventory(site_uuid: str, include_bgp: bool = False, filter_query: str | None = None) -> dict:
    """Return fabrics, switches and VRFs associated to one AFC site."""
    return {
        "site_uuid": site_uuid,
        "fabrics": _client().list_afc_site_fabrics(site_uuid=site_uuid, filter_query=filter_query),
        "switches": _client().list_afc_site_switches(
            site_uuid=site_uuid,
            include_bgp=include_bgp,
            filter_query=filter_query,
        ),
        "vrfs": _client().list_afc_site_vrfs(site_uuid=site_uuid, filter_query=filter_query),
    }


@mcp.tool()
def get_network_overview() -> dict:
    """Aggregate key network objects and status distributions in one call."""
    switches = _client().list_switches(include_software=True)
    fabrics = _client().list_fabrics(include_switches=True)
    vrfs = _client().list_vrfs(include_bgp=True, include_ospf=True, include_networks=True)
    evpn = _client().list_evpn()

    switch_items = _items_from_response(switches)
    fabric_items = _items_from_response(fabrics)

    return {
        "switches": {
            "count": switches.get("count", len(switch_items)),
            "status_by_health": _status_breakdown(switch_items, "health", fallback_key="status"),
        },
        "fabrics": {
            "count": fabrics.get("count", len(fabric_items)),
            "status_by_health": _status_breakdown(fabric_items, "health"),
        },
        "vrfs": {
            "count": vrfs.get("count", len(_items_from_response(vrfs))),
        },
        "evpn": {
            "count": evpn.get("count", len(_items_from_response(evpn))),
        },
        "note": "Use detailed tools for per-VRF BGP/OSPF and overlay/underlay state.",
    }


@mcp.tool()
def list_health_alerts(
    event_type: str | None = None,
    only_unacknowledged: bool = False,
    filter_query: str | None = None,
) -> dict:
    """List active AFC health alerts with a breakdown by severity.

    Set only_unacknowledged=True to hide alerts already acknowledged by an operator.
    """
    data = _client().list_health_alerts(event_type=event_type, filter_query=filter_query)
    items = _items_from_response(data)
    if only_unacknowledged:
        items = [item for item in items if not item.get("acknowledged", False)]
    return {
        "count": len(items),
        "severity_breakdown": _status_breakdown(items, "health_issue_severity"),
        "event_type_breakdown": _status_breakdown(items, "event_type"),
        "result": items,
    }


@mcp.tool()
def run_health_check(include_platform: bool = True, include_routing: bool = True) -> dict:
    """Run an aggregated health check across AFC alerts, switches and fabrics.

    Combines active health alerts, switch health, fabric health, BGP/OSPF neighbor
    adjacencies (when include_routing) and (optionally) HA cluster and license status
    into a single overall verdict.
    """
    checks: dict[str, Any] = {}
    problems: list[str] = []
    statuses: list[str] = []

    # Active health alerts
    try:
        alerts_data = _client().list_health_alerts()
        alert_items = _items_from_response(alerts_data)
        unacknowledged = [item for item in alert_items if not item.get("acknowledged", False)]
        severities = [str(item.get("health_issue_severity", "unknown")) for item in unacknowledged]
        alert_status = _worst_status(severities) if unacknowledged else "healthy"
        statuses.append(alert_status)
        checks["health_alerts"] = {
            "status": alert_status,
            "total": len(alert_items),
            "unacknowledged": len(unacknowledged),
            "severity_breakdown": _status_breakdown(unacknowledged, "health_issue_severity"),
            "alerts": unacknowledged,
        }
        if unacknowledged:
            problems.append(f"{len(unacknowledged)} unacknowledged health alert(s)")
    except Exception as exc:  # noqa: BLE001 - surface probe failure without aborting the check
        checks["health_alerts"] = {"status": "error", "error": str(exc)}
        statuses.append("critical")
        problems.append("unable to retrieve health alerts")

    # Switch health
    try:
        switches = _client().list_switches(include_software=True)
        switch_items = _items_from_response(switches)
        unhealthy_switches = _unhealthy_items(switch_items, "health", fallback_key="status")
        switch_status = _worst_status(
            [str(item.get("health") or item.get("status") or "unknown") for item in switch_items]
        )
        statuses.append(switch_status)
        checks["switches"] = {
            "status": switch_status,
            "count": switches.get("count", len(switch_items)),
            "status_by_health": _status_breakdown(switch_items, "health", fallback_key="status"),
            "unhealthy": [
                {
                    "uuid": item.get("uuid"),
                    "name": item.get("name"),
                    "health": item.get("health") or item.get("status"),
                }
                for item in unhealthy_switches
            ],
        }
        if unhealthy_switches:
            problems.append(f"{len(unhealthy_switches)} switch(es) not healthy")
    except Exception as exc:  # noqa: BLE001
        checks["switches"] = {"status": "error", "error": str(exc)}
        statuses.append("critical")
        problems.append("unable to retrieve switch health")

    # Fabric health
    try:
        fabrics = _client().list_fabrics(include_switches=True)
        fabric_items = _items_from_response(fabrics)
        unhealthy_fabrics = _unhealthy_items(fabric_items, "health")
        fabric_status = _worst_status([str(item.get("health") or "unknown") for item in fabric_items])
        statuses.append(fabric_status)
        checks["fabrics"] = {
            "status": fabric_status,
            "count": fabrics.get("count", len(fabric_items)),
            "status_by_health": _status_breakdown(fabric_items, "health"),
            "unhealthy": [
                {"uuid": item.get("uuid"), "name": item.get("name"), "health": item.get("health")}
                for item in unhealthy_fabrics
            ],
        }
        if unhealthy_fabrics:
            problems.append(f"{len(unhealthy_fabrics)} fabric(s) not healthy")
    except Exception as exc:  # noqa: BLE001
        checks["fabrics"] = {"status": "error", "error": str(exc)}
        statuses.append("critical")
        problems.append("unable to retrieve fabric health")

    # BGP and OSPF neighbor adjacencies (per VRF)
    if include_routing:
        try:
            vrfs = _client().list_vrfs(include_bgp=True, include_ospf=True, include_networks=False)
            vrf_items = _items_from_response(vrfs)
            bgp_down: list[dict[str, Any]] = []
            ospf_down: list[dict[str, Any]] = []
            routing_errors: list[str] = []
            for vrf in vrf_items:
                vrf_uuid = vrf.get("uuid")
                vrf_name = vrf.get("name")
                if not vrf_uuid:
                    continue
                try:
                    bgp = _client().get_vrf_bgp_status(vrf_uuid=vrf_uuid)
                    bgp_down.extend(_bgp_down_neighbors(vrf_uuid, vrf_name, bgp))
                except Exception as exc:  # noqa: BLE001
                    routing_errors.append(f"bgp {vrf_name or vrf_uuid}: {exc}")
                try:
                    ospf = _client().get_vrf_ospf_neighbors(vrf_uuid=vrf_uuid)
                    ospf_down.extend(_ospf_down_neighbors(vrf_uuid, vrf_name, ospf))
                except Exception as exc:  # noqa: BLE001
                    routing_errors.append(f"ospf {vrf_name or vrf_uuid}: {exc}")
            routing_status = "critical" if (bgp_down or ospf_down) else "healthy"
            statuses.append(routing_status)
            checks["routing"] = {
                "status": routing_status,
                "vrfs_checked": len(vrf_items),
                "bgp_down_neighbors": bgp_down,
                "ospf_down_neighbors": ospf_down,
                "errors": routing_errors,
            }
            if bgp_down:
                problems.append(f"{len(bgp_down)} BGP neighbor(s) not Established")
            if ospf_down:
                problems.append(f"{len(ospf_down)} OSPF neighbor(s) not healthy")
        except Exception as exc:  # noqa: BLE001
            checks["routing"] = {"status": "error", "error": str(exc)}
            statuses.append("critical")
            problems.append("unable to retrieve routing neighbor status")

    # Optional platform diagnostics (HA cluster and licensing)
    if include_platform:
        try:
            checks["ha_status"] = _client().get_ha_status().get("result", {})
        except Exception as exc:  # noqa: BLE001
            checks["ha_status"] = {"status": "error", "error": str(exc)}
        try:
            checks["license_status"] = _client().get_license_status().get("result", {})
        except Exception as exc:  # noqa: BLE001
            checks["license_status"] = {"status": "error", "error": str(exc)}

    overall = _worst_status(statuses)
    return {
        "service": "afc-mcp",
        "overall_status": overall,
        "summary": problems or ["no health issues detected"],
        "checks": checks,
    }


@mcp.tool()
def list_integrations(include_configurations: bool = True, filter_query: str | None = None) -> dict:
    """List AFC integration packs, their remote servers and connection state.

    Answers "what integrations are in place, which remote servers and their status".
    Each configuration is a discrete connection (e.g. a vCenter) with its host and state.
    """
    data = _client().list_integrations(include_configurations=include_configurations, filter_query=filter_query)
    packs = _items_from_response(data)
    summary: list[dict[str, Any]] = []
    for pack in packs:
        configs = pack.get("configurations") or []
        for cfg in configs:
            summary.append(
                {
                    "pack": pack.get("name"),
                    "config_name": cfg.get("name"),
                    "remote_server": cfg.get("host"),
                    "connection_state": cfg.get("connection_state"),
                    "connection_fault": cfg.get("connection_fault_string") or None,
                    "enabled": cfg.get("enabled"),
                    "last_connection": cfg.get("last_connection"),
                    "uuid": cfg.get("uuid"),
                }
            )
    return {
        "count": len(packs),
        "packs": [
            {
                "name": pack.get("name"),
                "version": pack.get("version"),
                "features": pack.get("features", []),
                "configuration_count": len(pack.get("configurations") or []),
            }
            for pack in packs
        ],
        "connections": summary,
        "state_breakdown": _status_breakdown(summary, "connection_state"),
    }


def _vmw(obj: dict[str, Any]) -> dict[str, Any]:
    """Return the vmware-specific associated object, or an empty dict."""
    associated = obj.get("associated_objects") or {}
    vmware = associated.get("vmware")
    return vmware if isinstance(vmware, dict) else {}


def _vmware_host_location(host_vmw: dict[str, Any]) -> dict[str, Any]:
    """Extract a VMware host's placement (vCenter / datacenter / cluster)."""
    datacenter = host_vmw.get("datacenter") or {}
    cluster = host_vmw.get("cluster") or {}
    return {
        "vcenter": host_vmw.get("vsphere_uuid"),
        "datacenter": datacenter.get("name"),
        "cluster": cluster.get("name"),
        "domain": host_vmw.get("domain_name"),
    }


def _summarize_vmware_host(host: dict[str, Any]) -> dict[str, Any]:
    """Flatten one host_generic (vmware) into hosts/vswitches/portgroups/vms views."""
    host_vmw = _vmw(host)
    vswitches: list[dict[str, Any]] = []
    portgroups: list[dict[str, Any]] = []
    for vsw in host.get("vswitches") or []:
        vmw = _vmw(vsw)
        vsw_name = vsw.get("name") or vmw.get("name")
        vsw_entry = {
            "name": vsw_name,
            "type": vmw.get("type"),
            "moref": vmw.get("moref"),
            "uuid": vmw.get("uuid"),
            "portgroup_count": len(vmw.get("portgroups") or []),
        }
        vswitches.append(vsw_entry)
        for pg in vmw.get("portgroups") or []:
            portgroups.append(
                {
                    "name": pg.get("name"),
                    "vswitch": vsw_name,
                    "type": pg.get("type"),
                    "uplink": pg.get("uplink", False),
                    "vlans": pg.get("vlans"),
                    "primary_vlan": pg.get("primary_vlan"),
                    "uuid": pg.get("uuid"),
                }
            )
    nics: list[dict[str, Any]] = []
    for nic in host.get("nics") or []:
        nics.append(
            {
                "name": nic.get("name"),
                "mac_addresses": nic.get("mac_addresses"),
                "link_state": nic.get("link_state"),
                "connection_status": nic.get("connection_status"),
                "switch_uuid": nic.get("downlink_switch_uuid"),
                "switch_port": nic.get("downlink_switch_port_id") or nic.get("switch_port_id"),
            }
        )
    vms: list[dict[str, Any]] = []
    for vm in host.get("vms") or []:
        vm_vmw = _vmw(vm)
        vms.append(
            {
                "name": vm.get("name"),
                "power_state": vm.get("power_state") or vm_vmw.get("power_state"),
                "os_type": vm_vmw.get("os_type"),
                "guest_hostname": vm_vmw.get("hostname"),
                "infrastructure_tags": vm.get("infrastructure_tags") or [],
                "nic_count": len(vm.get("nics") or []),
            }
        )
    return {
        "name": host.get("name"),
        "host_uuid": host_vmw.get("uuid"),
        "type": host_vmw.get("type"),
        "location": _vmware_host_location(host_vmw),
        "nic_status": _status_breakdown(nics, "connection_status", "link_state"),
        "vm_power_states": _status_breakdown(vms, "power_state"),
        "vswitches": vswitches,
        "portgroups": portgroups,
        "physical_nics": nics,
        "vms": vms,
    }


@mcp.tool()
def get_vmware_inventory(host_name: str | None = None) -> dict:
    """List VMware hosts and, for each, its vSwitches, Port Groups and VMs.

    Optionally filter to a single ESXi host by name (exact or substring, case-insensitive).
    """
    data = _client().list_hosts(all_data=True, vendor="vmware")
    hosts = _items_from_response(data)
    if host_name:
        needle = host_name.lower()
        hosts = [h for h in hosts if needle in str(h.get("name", "")).lower()]
    summaries = [_summarize_vmware_host(h) for h in hosts]
    all_vms = [vm for h in summaries for vm in h["vms"]]
    return {
        "host_count": len(summaries),
        "totals": {
            "vswitches": sum(len(h["vswitches"]) for h in summaries),
            "portgroups": sum(len(h["portgroups"]) for h in summaries),
            "vms": sum(len(h["vms"]) for h in summaries),
        },
        "vm_power_states": _status_breakdown(all_vms, "power_state"),
        "hosts": summaries,
    }


@mcp.tool()
def list_vmware_integrations() -> dict:
    """List VMware vCenter (vSphere) integrations and their connection status.

    Focuses on the vSphere integration pack: one entry per configured vCenter, with
    its server address, connection state and any fault message.
    """
    data = _client().list_integrations(include_configurations=True)
    packs = _items_from_response(data)
    vcenters: list[dict[str, Any]] = []
    for pack in packs:
        pack_name = str(pack.get("name") or "").lower()
        if not any(tag in pack_name for tag in ("vsphere", "vmware", "vcenter")):
            continue
        for cfg in pack.get("configurations") or []:
            vcenters.append(
                {
                    "name": cfg.get("name"),
                    "vcenter_server": cfg.get("host"),
                    "connection_state": cfg.get("connection_state"),
                    "connection_fault": cfg.get("connection_fault_string") or None,
                    "enabled": cfg.get("enabled"),
                    "last_connection": cfg.get("last_connection"),
                    "last_cache_sync": cfg.get("last_cache_sync"),
                    "uuid": cfg.get("uuid"),
                }
            )
    return {
        "count": len(vcenters),
        "state_breakdown": _status_breakdown(vcenters, "connection_state"),
        "vcenters": vcenters,
    }


@mcp.tool()
def list_vmware_vms(power_state: str | None = None, host_name: str | None = None) -> dict:
    """List all VMware VMs with their power status and placement.

    Returns a flat inventory of virtual machines, each with its power state and location
    (ESXi host, cluster, datacenter and vCenter). Optionally filter by power_state
    (on/off/suspended/unknown) or by ESXi host name (substring, case-insensitive).
    """
    data = _client().list_hosts(all_data=True, vendor="vmware")
    hosts = _items_from_response(data)
    host_needle = host_name.lower() if host_name else None
    state_needle = power_state.lower() if power_state else None
    vms: list[dict[str, Any]] = []
    for host in hosts:
        esxi_name = host.get("name")
        if host_needle and host_needle not in str(esxi_name).lower():
            continue
        host_vmw = _vmw(host)
        location = _vmware_host_location(host_vmw)
        for vm in host.get("vms") or []:
            vm_vmw = _vmw(vm)
            state = vm.get("power_state") or vm_vmw.get("power_state")
            if state_needle and str(state).lower() != state_needle:
                continue
            ip_addresses = [
                ip for vnic in vm.get("nics") or [] if (ip := _vmw(vnic).get("ip_address"))
            ]
            vms.append(
                {
                    "name": vm.get("name"),
                    "power_state": state,
                    "os_type": vm_vmw.get("os_type"),
                    "guest_hostname": vm_vmw.get("hostname"),
                    "ip_addresses": ip_addresses,
                    "infrastructure_tags": vm.get("infrastructure_tags") or [],
                    "location": {
                        "esxi_host": esxi_name,
                        "host_uuid": vm_vmw.get("host_uuid") or host_vmw.get("uuid"),
                        **location,
                    },
                }
            )
    return {
        "count": len(vms),
        "power_state_breakdown": _status_breakdown(vms, "power_state"),
        "vms": vms,
    }


def _uplink_nic_uuids(portgroup: dict[str, Any], vswitch_vmw: dict[str, Any]) -> list[str]:
    """Return the physical host NIC UUIDs carrying a port group's traffic.

    Prefers the port group's own (active) uplinks; for distributed port groups whose
    uplinks live on the vSwitch's uplink port group, falls back to those.
    """
    uuids = list(portgroup.get("active_host_nic_uuids") or portgroup.get("host_nic_uuids") or [])
    if uuids:
        return uuids
    for pg in vswitch_vmw.get("portgroups") or []:
        is_uplink = pg.get("uplink") or str(pg.get("type", "")).endswith("_uplink")
        if is_uplink:
            uuids.extend(pg.get("active_host_nic_uuids") or pg.get("host_nic_uuids") or [])
    return uuids


@mcp.tool()
def get_vm_attachment(vm_name: str, resolve_switch_names: bool = True) -> dict:
    """Trace the end-to-end network attachment of a VMware VM.

    For the given VM, returns each virtual NIC mapped to its Port Group, vSwitch and,
    following the host uplinks, the physical switch and switch port it lands on.
    """
    data = _client().list_hosts(all_data=True, vendor="vmware")
    hosts = _items_from_response(data)

    needle = vm_name.lower()
    matched: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for host in hosts:
        for vm in host.get("vms") or []:
            name = str(vm.get("name", ""))
            if needle == name.lower() or needle in name.lower():
                matched.append((host, vm))

    if not matched:
        return {"vm_name": vm_name, "found": False, "message": "No matching VMware VM found."}

    # Optional switch UUID -> name resolution
    switch_names: dict[str, str] = {}
    port_to_switch: dict[str, dict[str, Any]] = {}
    if resolve_switch_names:
        try:
            for sw in _items_from_response(_client().list_switches(include_ports=True)):
                sw_uuid = sw.get("uuid")
                if sw_uuid:
                    switch_names[sw_uuid] = sw.get("name")
                for port in sw.get("ports") or []:
                    if port.get("uuid"):
                        port_to_switch[port["uuid"]] = {
                            "switch_uuid": sw_uuid,
                            "switch_name": sw.get("name"),
                            "switch_port": port.get("name"),
                        }
        except Exception:  # noqa: BLE001 - name resolution is best-effort
            switch_names = {}
            port_to_switch = {}

    results: list[dict[str, Any]] = []
    for host, vm in matched:
        # Index this host's port groups and physical NICs
        pg_index: dict[str, tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = {}
        moref_index: dict[str, tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = {}
        for vsw in host.get("vswitches") or []:
            vmw = _vmw(vsw)
            for pg in vmw.get("portgroups") or []:
                entry = (pg, vsw, vmw)
                if pg.get("uuid"):
                    pg_index[pg["uuid"]] = entry
                if pg.get("moref"):
                    moref_index[pg["moref"]] = entry
        nic_index: dict[str, dict[str, Any]] = {}
        for nic in host.get("nics") or []:
            nic_uuid = _vmw(nic).get("uuid")
            if nic_uuid:
                nic_index[nic_uuid] = nic

        vnic_results: list[dict[str, Any]] = []
        for vnic in vm.get("nics") or []:
            vmw_nic = _vmw(vnic)
            pg_uuid = vmw_nic.get("portgroup_uuid")
            pg_moref = vmw_nic.get("dvportgroup_moref") or vmw_nic.get("portgroup_moref")
            entry = pg_index.get(pg_uuid) if pg_uuid else None
            if entry is None and pg_moref:
                entry = moref_index.get(pg_moref)

            attachment = {
                "vnic_name": vnic.get("name"),
                "mac_address": vmw_nic.get("mac_address"),
                "ip_addresses": vnic.get("ip_addresses"),
                "vlan": vmw_nic.get("vlan"),
                "port_group": None,
                "vswitch": None,
                "vswitch_type": None,
                "physical_uplinks": [],
            }
            if entry is not None:
                pg, vsw, vmw = entry
                attachment["port_group"] = pg.get("name")
                attachment["vswitch"] = vsw.get("name") or vmw.get("name")
                attachment["vswitch_type"] = vmw.get("type")
                for nic_uuid in _uplink_nic_uuids(pg, vmw):
                    nic = nic_index.get(nic_uuid)
                    if not nic:
                        continue
                    sw_uuid = nic.get("downlink_switch_uuid")
                    port_uuid = nic.get("port_uuid")
                    port_info = port_to_switch.get(port_uuid) if port_uuid else None
                    resolved_switch_uuid = sw_uuid or (port_info or {}).get("switch_uuid")
                    switch_name = None
                    if resolved_switch_uuid:
                        switch_name = switch_names.get(resolved_switch_uuid)
                    if switch_name is None and port_info:
                        switch_name = port_info.get("switch_name")
                    switch_port = (
                        nic.get("downlink_switch_port_id")
                        or nic.get("switch_port_id")
                        or (port_info or {}).get("switch_port")
                    )
                    attachment["physical_uplinks"].append(
                        {
                            "host_nic": nic.get("name") or _vmw(nic).get("moref"),
                            "nic_mac": _vmw(nic).get("mac_address"),
                            "link_state": nic.get("link_state"),
                            "switch_uuid": resolved_switch_uuid,
                            "switch_name": switch_name,
                            "switch_mac_address": nic.get("switch_mac_address") or None,
                            "switch_port": switch_port,
                            "switch_port_uuid": port_uuid,
                        }
                    )
            vnic_results.append(attachment)

        results.append(
            {
                "vm_name": vm.get("name"),
                "power_state": vm.get("power_state"),
                "esxi_host": host.get("name"),
                "vnics": vnic_results,
            }
        )

    return {"vm_name": vm_name, "found": True, "matches": results}


class _SecurityMiddleware:
    """Optional Bearer authentication for the MCP endpoint (ASGI).

    When authentication is disabled this is a zero-cost passthrough. Only the
    MCP path (default ``/mcp``) is guarded; any other path is left untouched.
    """

    def __init__(self, app, *, auth_enabled, token_store, mcp_path, trust_forwarded):
        self._app = app
        self._auth_enabled = auth_enabled
        self._token_store = token_store
        self._mcp_path = mcp_path
        self._trust_forwarded = trust_forwarded

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self._auth_enabled:
            await self._app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not path.startswith(self._mcp_path):
            await self._app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers", [])}
        src_ip = self._client_ip(scope, headers)

        # LOCKED mode: auth required but no token exists yet.
        if self._token_store is None or len(self._token_store) == 0:
            logger.warning("🔒 MCP request refused — server LOCKED (no token "
                           "configured) from %s %s", src_ip, path)
            await self._send_503_locked(send)
            return

        actor = self._resolve_actor(headers)
        if actor is None:
            logger.warning("🚫 Rejected unauthenticated request from %s %s", src_ip, path)
            await self._send_401(send)
            return

        await self._app(scope, receive, send)

    def _resolve_actor(self, headers: dict) -> str | None:
        auth = headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[7:].strip()
        return self._token_store.resolve(token)

    def _client_ip(self, scope, headers: dict) -> str:
        if self._trust_forwarded:
            xff = headers.get("x-forwarded-for")
            if xff:
                return xff.split(",")[0].strip()
        client = scope.get("client")
        return client[0] if client else "unknown"

    @staticmethod
    async def _send_401(send) -> None:
        payload = json.dumps({"error": "Missing or invalid bearer token"}).encode()
        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode()),
                (b"www-authenticate", b"Bearer"),
            ],
        })
        await send({"type": "http.response.body", "body": payload})

    @staticmethod
    async def _send_503_locked(send) -> None:
        payload = json.dumps({
            "error": "Service locked: authentication is enabled but no token is "
                     "configured. Create the first token with "
                     "`docker compose exec afc-mcp python afc_token_manager.py "
                     "generate --name <client>`, then restart the container.",
        }).encode()
        await send({
            "type": "http.response.start",
            "status": 503,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode()),
                (b"retry-after", b"0"),
            ],
        })
        await send({"type": "http.response.body", "body": payload})


if __name__ == "__main__":
    import uvicorn

    _init_security()

    if _AUTH_ENABLED:
        app = _SecurityMiddleware(
            mcp.streamable_http_app(),
            auth_enabled=_AUTH_ENABLED,
            token_store=_token_store,
            mcp_path=_MCP_PATH,
            trust_forwarded=_TRUST_FORWARDED,
        )
        uvicorn.run(app, host=_host, port=_port)
    else:
        mcp.run(transport="streamable-http")
