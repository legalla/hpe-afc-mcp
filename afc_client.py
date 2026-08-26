"""Aruba Fabric Composer API client for read-only inventory and state data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class AFCClient:
    """HTTP client for Aruba Fabric Composer API."""

    base_url: str
    username: str
    password: str
    verify_ssl: bool = False
    timeout: int = 30

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        self._session = requests.Session()
        self._token: str | None = None

    def connection_info(self) -> dict:
        """Return non-sensitive connection metadata for diagnostics."""
        return {
            "base_url": self.base_url,
            "verify_ssl": self.verify_ssl,
            "timeout": self.timeout,
            "configured": bool(self.base_url and self.username and self.password),
            "authenticated": bool(self._token),
        }

    def _base_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json; version=1.0",
            "Content-Type": "application/json; version=1.0",
        }
        if self._token:
            headers["Authorization"] = self._token
        return headers

    def _auth_headers(self) -> dict[str, str]:
        headers = self._base_headers()
        headers["X-Auth-Username"] = self.username
        headers["X-Auth-Password"] = self.password
        return headers

    def _authenticate(self) -> None:
        if not self.base_url or not self.username or not self.password:
            raise ValueError("AFC client is not configured. Set AFC_BASE_URL, AFC_USERNAME and AFC_PASSWORD.")

        url = f"{self.base_url}/api/auth/token"
        response = self._session.post(
            url,
            headers=self._auth_headers(),
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        response.raise_for_status()

        payload = response.json() if response.content else {}
        token = payload.get("result") if isinstance(payload, dict) else None
        if not token or not isinstance(token, str):
            raise RuntimeError(f"Unable to authenticate to AFC: unexpected token response: {payload}")
        self._token = token

    def _clean_params(self, params: dict[str, Any] | None) -> dict[str, Any] | None:
        if not params:
            return None

        cleaned: dict[str, Any] = {}
        for key, value in params.items():
            if value is None:
                continue
            if isinstance(value, list):
                if not value:
                    continue
                cleaned[key] = ",".join(str(v) for v in value)
                continue
            cleaned[key] = value
        return cleaned or None

    def _raise_http_error(self, response: requests.Response) -> None:
        try:
            payload = response.json()
        except ValueError:
            response.raise_for_status()
            return

        if isinstance(payload, dict):
            message = payload.get("error") or payload.get("message") or payload
            raise RuntimeError(f"AFC API error ({response.status_code}): {message}")
        response.raise_for_status()

    def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not self._token:
            self._authenticate()

        assert self._token is not None
        url = f"{self.base_url}/api{path}"
        cleaned_params = self._clean_params(params)

        response = self._session.request(
            method=method,
            url=url,
            headers=self._base_headers(),
            params=cleaned_params,
            json=json_body,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )

        if response.status_code == 401:
            self._authenticate()
            response = self._session.request(
                method=method,
                url=url,
                headers=self._base_headers(),
                params=cleaned_params,
                json=json_body,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )

        if response.status_code >= 400:
            self._raise_http_error(response)

        if not response.content:
            return {}
        payload = response.json()
        return payload if isinstance(payload, dict) else {"result": payload}

    # Inventory and platform
    def get_system(self) -> dict[str, Any]:
        return self._request("GET", "/system")

    def list_switches(
        self,
        include_ports: bool = False,
        include_software: bool = False,
        include_tags: bool = False,
        filter_query: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/switches",
            params={
                "ports": include_ports,
                "software": include_software,
                "tags": include_tags,
                "filter": filter_query,
                "page": page,
                "page_size": page_size,
            },
        )

    def get_switch(
        self,
        switch_uuid: str,
        include_ports: bool = True,
        include_software: bool = True,
        include_tags: bool = True,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/switches/{switch_uuid}",
            params={
                "ports": include_ports,
                "software": include_software,
                "tags": include_tags,
            },
        )

    def list_fabrics(
        self,
        include_switches: bool = True,
        filter_query: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/fabrics",
            params={
                "switches": include_switches,
                "filter": filter_query,
                "page": page,
                "page_size": page_size,
            },
        )

    def get_fabric(self, fabric_uuid: str, include_switches: bool = True) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/fabrics/{fabric_uuid}",
            params={"switches": include_switches},
        )

    # Fabric leaf-spine topology (underlay/overlay building blocks)
    def list_leaf_spine(
        self,
        fabrics: list[str] | None = None,
        include_interface: bool = False,
        count_only: bool = False,
        filter_query: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/fabrics/leaf_spine",
            params={
                "fabrics": fabrics,
                "leaf_spine_interface": include_interface,
                "count_only": count_only,
                "filter": filter_query,
                "page": page,
                "page_size": page_size,
            },
        )

    def list_fabric_leaf_spine(
        self,
        fabric_uuid: str,
        include_interface: bool = False,
        count_only: bool = False,
        filter_query: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/fabrics/{fabric_uuid}/leaf_spine",
            params={
                "leaf_spine_interface": include_interface,
                "count_only": count_only,
                "filter": filter_query,
                "page": page,
                "page_size": page_size,
            },
        )

    def get_leaf_spine(
        self,
        fabric_uuid: str,
        leaf_spine_uuid: str,
        include_interface: bool = False,
        filter_query: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/fabrics/{fabric_uuid}/leaf_spine/{leaf_spine_uuid}",
            params={
                "leaf_spine_interface": include_interface,
                "filter": filter_query,
            },
        )

    def list_l2_leaf_spine(
        self,
        fabrics: list[str] | None = None,
        include_lag: bool = False,
        count_only: bool = False,
        filter_query: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/fabrics/l2_leaf_spine",
            params={
                "fabrics": fabrics,
                "include_lag": include_lag,
                "count_only": count_only,
                "filter": filter_query,
                "page": page,
                "page_size": page_size,
            },
        )

    def list_vsx(
        self,
        fabrics: list[str] | None = None,
        include_isl_lag: bool = False,
        include_keep_alive_interface: bool = False,
        count_only: bool = False,
        filter_query: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/fabrics/vsx",
            params={
                "fabrics": fabrics,
                "isl_lag": include_isl_lag,
                "keep_alive_interface": include_keep_alive_interface,
                "count_only": count_only,
                "filter": filter_query,
                "page": page,
                "page_size": page_size,
            },
        )

    def list_fabric_vsx(
        self,
        fabric_uuid: str,
        include_isl_lag: bool = False,
        include_keep_alive_interface: bool = False,
        count_only: bool = False,
        filter_query: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/fabrics/{fabric_uuid}/vsx",
            params={
                "isl_lag": include_isl_lag,
                "keep_alive_interface": include_keep_alive_interface,
                "count_only": count_only,
                "filter": filter_query,
                "page": page,
                "page_size": page_size,
            },
        )

    def get_vsx(
        self,
        fabric_uuid: str,
        vsx_uuid: str,
        include_isl_lag: bool = False,
        include_keep_alive_interface: bool = False,
        filter_query: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/fabrics/{fabric_uuid}/vsx/{vsx_uuid}",
            params={
                "isl_lag": include_isl_lag,
                "keep_alive_interface": include_keep_alive_interface,
                "filter": filter_query,
            },
        )

    def list_subleaf_leaf(
        self,
        fabrics: list[str] | None = None,
        include_lag: bool = False,
        count_only: bool = False,
        filter_query: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/fabrics/subleaf_leaf",
            params={
                "fabrics": fabrics,
                "include_lag": include_lag,
                "count_only": count_only,
                "filter": filter_query,
                "page": page,
                "page_size": page_size,
            },
        )

    def get_subleaf_leaf_peer(
        self,
        fabric_uuid: str,
        peer_uuid: str,
        include_lag: bool = False,
        filter_query: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/fabrics/{fabric_uuid}/subleaf_leaf/peers/{peer_uuid}",
            params={
                "include_lag": include_lag,
                "filter": filter_query,
            },
        )

    # Multi-Fabric (Multi-Hop VXLAN) — inter-fabric VXLAN stitching via border leaders
    def list_multi_hop_vxlan(
        self,
        count_only: bool = False,
        filter_query: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/fabrics/multi_hop_vxlan",
            params={
                "count_only": count_only,
                "filter": filter_query,
                "page": page,
                "page_size": page_size,
            },
        )

    def list_fabric_multi_hop_vxlan(
        self,
        fabric_uuid: str,
        count_only: bool = False,
        filter_query: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/fabrics/{fabric_uuid}/multi_hop_vxlan",
            params={
                "count_only": count_only,
                "filter": filter_query,
                "page": page,
                "page_size": page_size,
            },
        )

    def get_multi_hop_vxlan(
        self,
        fabric_uuid: str,
        uuid: str,
        filter_query: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/fabrics/{fabric_uuid}/multi_hop_vxlan/{uuid}",
            params={"filter": filter_query},
        )

    # Stretched VLAN (EVPN Multi-Site) — VLANs stretched across fabrics
    def list_evpn_multi_site(
        self,
        fabrics: list[str] | None = None,
        count_only: bool = False,
        filter_query: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/evpn/multi_site",
            params={
                "fabrics": fabrics,
                "count_only": count_only,
                "filter": filter_query,
                "page": page,
                "page_size": page_size,
            },
        )

    def get_evpn_multi_site(
        self,
        uuid: str,
        filter_query: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/evpn/multi_site/{uuid}",
            params={"filter": filter_query},
        )

    # NTP / DNS client configurations
    def list_ntp_configurations(
        self,
        fabric: str | None = None,
        switch: str | None = None,
        in_use_only: bool = False,
        count_only: bool = False,
        filter_query: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/ntp_client_configurations",
            params={
                "fabric": fabric,
                "switch": switch,
                "in_use_only": in_use_only,
                "count_only": count_only,
                "filter": filter_query,
                "page": page,
                "page_size": page_size,
            },
        )

    def list_dns_configurations(
        self,
        fabric: str | None = None,
        switch: str | None = None,
        in_use_only: bool = False,
        management_software: bool | None = None,
        count_only: bool = False,
        filter_query: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/dns_client_configurations",
            params={
                "fabric": fabric,
                "switch": switch,
                "in_use_only": in_use_only,
                "management_software": management_software,
                "count_only": count_only,
                "filter": filter_query,
                "page": page,
                "page_size": page_size,
            },
        )

    # VRF and routing domains
    def list_vrfs(
        self,
        include_bgp: bool = True,
        include_ospf: bool = True,
        include_networks: bool = True,
        include_interfaces: bool = False,
        filter_query: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/vrfs",
            params={
                "include_bgp_global": include_bgp,
                "include_bgp": include_bgp,
                "include_ospf_global": include_ospf,
                "include_ospf": include_ospf,
                "include_networks": include_networks,
                "ip_interfaces": include_interfaces,
                "filter": filter_query,
                "page": page,
                "page_size": page_size,
            },
        )

    def get_vrf(
        self,
        vrf_uuid: str,
        include_bgp: bool = True,
        include_ospf: bool = True,
        include_networks: bool = True,
        include_interfaces: bool = True,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/vrfs/{vrf_uuid}",
            params={
                "include_bgp_global": include_bgp,
                "include_bgp": include_bgp,
                "include_ospf_global": include_ospf,
                "include_ospf": include_ospf,
                "include_networks": include_networks,
                "ip_interfaces": include_interfaces,
            },
        )

    def list_vrf_switches(self, vrf_uuid: str, filter_query: str | None = None) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/vrfs/{vrf_uuid}/switches",
            params={"filter": filter_query},
        )

    def get_vrf_bgp_status(
        self,
        vrf_uuid: str,
        switch_uuid: str | None = None,
        include_neighbors: bool = True,
        filter_query: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/vrfs/{vrf_uuid}/bgp/status",
            params={
                "switch_uuid": switch_uuid,
                "neighbors": include_neighbors,
                "filter": filter_query,
            },
        )

    def get_vrf_bgp_summary(
        self,
        vrf_uuid: str,
        switch_uuid: str | None = None,
        include_neighbors: bool = True,
        filter_query: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/vrfs/{vrf_uuid}/bgp/summary",
            params={
                "switch_uuid": switch_uuid,
                "neighbors": include_neighbors,
                "filter": filter_query,
            },
        )

    def get_vrf_ospf_neighbors(self, vrf_uuid: str, filter_query: str | None = None) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/vrfs/{vrf_uuid}/ospf_neighbors/status",
            params={"filter": filter_query},
        )

    def get_vrf_ospf_summary(
        self,
        vrf_uuid: str,
        switch_uuid: str | None = None,
        ospf_router_uuid: str | None = None,
        filter_query: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/vrfs/{vrf_uuid}/ospf_routers/summary",
            params={
                "switch_uuid": switch_uuid,
                "ospf_router_uuid": ospf_router_uuid,
                "filter": filter_query,
            },
        )

    def get_vrf_overlay(self, vrf_uuid: str, filter_query: str | None = None) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/vrfs/{vrf_uuid}/overlay",
            params={"filter": filter_query},
        )

    def get_vrf_underlay(self, vrf_uuid: str, filter_query: str | None = None) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/vrfs/{vrf_uuid}/underlay",
            params={"filter": filter_query},
        )

    def list_vrf_ip_routes(
        self,
        vrf_uuid: str,
        switches: list[str] | None = None,
        count_only: bool = False,
        filter_query: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/vrfs/{vrf_uuid}/ip_tables/ip_route",
            params={
                "switches": switches,
                "count_only": count_only,
                "filter": filter_query,
                "page": page,
                "page_size": page_size,
            },
        )

    def list_vrf_arp(
        self,
        vrf_uuid: str,
        switches: list[str] | None = None,
        count_only: bool = False,
        filter_query: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/vrfs/{vrf_uuid}/ip_tables/arp",
            params={
                "switches": switches,
                "count_only": count_only,
                "filter": filter_query,
                "page": page,
                "page_size": page_size,
            },
        )

    def list_vrf_ip_interfaces(
        self,
        vrf_uuid: str,
        if_type: str | None = None,
        filter_query: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/vrfs/{vrf_uuid}/ip_interfaces",
            params={
                "if_type": if_type,
                "filter": filter_query,
            },
        )

    def get_vrf_ip_interfaces_status(
        self,
        vrf_uuid: str,
        switch_uuid: str | None = None,
        if_uuid: str | None = None,
        filter_query: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/vrfs/{vrf_uuid}/ip_interfaces/status",
            params={
                "switch_uuid": switch_uuid,
                "if_uuid": if_uuid,
                "filter": filter_query,
            },
        )

    def get_vrf_static_routes(self, vrf_uuid: str) -> dict[str, Any]:
        # AFC exposes no dedicated static-route listing endpoint; static routes
        # are returned nested in the VRF object via ip_static_routes=true.
        return self._request(
            "GET",
            f"/vrfs/{vrf_uuid}",
            params={
                "ip_static_routes": True,
                "include_bgp_global": False,
                "include_bgp": False,
                "include_ospf_global": False,
                "include_ospf": False,
                "include_networks": False,
                "ip_interfaces": False,
            },
        )

    # EVPN and virtual networking domains
    def list_evpn(
        self,
        fabrics: list[str] | None = None,
        switch_uuids: list[str] | None = None,
        filter_query: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/evpn",
            params={
                "fabrics": fabrics,
                "switch_uuids": switch_uuids,
                "filter": filter_query,
                "page": page,
                "page_size": page_size,
            },
        )

    def list_evpn_routes(
        self,
        switches: list[str] | None = None,
        filter_query: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/evpn/evpn_routes",
            params={
                "switches": switches,
                "filter": filter_query,
                "page": page,
                "page_size": page_size,
            },
        )

    # Optional AFC-site inventory views
    def list_afc_sites(self, filter_query: str | None = None) -> dict[str, Any]:
        return self._request("GET", "/hpe_anw/sites", params={"filter": filter_query})

    def list_afc_site_switches(
        self,
        site_uuid: str,
        include_bgp: bool = False,
        filter_query: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/hpe_anw/sites/{site_uuid}/switches",
            params={"include_bgp": include_bgp, "filter": filter_query},
        )

    def list_afc_site_fabrics(self, site_uuid: str, filter_query: str | None = None) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/hpe_anw/sites/{site_uuid}/fabrics",
            params={"filter": filter_query},
        )

    def list_afc_site_vrfs(self, site_uuid: str, filter_query: str | None = None) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/hpe_anw/sites/{site_uuid}/vrfs",
            params={"filter": filter_query},
        )

    # Health and platform diagnostics
    def list_health_alerts(
        self,
        count_only: bool = False,
        event_type: str | None = None,
        filter_query: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/chs/health_alerts",
            params={
                "count_only": count_only,
                "event_type": event_type,
                "filter": filter_query,
            },
        )

    def get_ha_status(self) -> dict[str, Any]:
        return self._request("GET", "/high_availability/status")

    def get_license_status(self) -> dict[str, Any]:
        return self._request("GET", "/licenses/status")

    # Integrations and virtualization inventory
    def list_integrations(self, include_configurations: bool = True, filter_query: str | None = None) -> dict[str, Any]:
        return self._request(
            "GET",
            "/integrations",
            params={"configurations": include_configurations, "filter": filter_query},
        )

    def list_hosts(
        self,
        all_data: bool = False,
        vendor: str | None = None,
        uuids: list[str] | None = None,
        count_only: bool = False,
        page: int | None = None,
        page_size: int | None = None,
        filter_query: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/hosts",
            params={
                "all_data": all_data,
                "vendor": vendor,
                "uuids": uuids,
                "count_only": count_only,
                "page": page,
                "page_size": page_size,
                "filter": filter_query,
            },
        )

    def get_host(self, host_uuid: str, all_data: bool = True) -> dict[str, Any]:
        return self._request("GET", f"/hosts/{host_uuid}", params={"all_data": all_data})
