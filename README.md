# afc-mcp

MCP server for Aruba Fabric Composer (AFC) focused on inventory, network state and
VMware vCenter/vSphere visibility. Read-only.

## Included

- `server.py`: FastMCP entrypoint exposing the MCP tools (transport: streamable-http).
- `afc_client.py`: AFC API client with auth token handling and mapped read-only endpoints.
- `Dockerfile`: container image for the MCP server.
- `docker-compose.yml`: local runtime (host port `8010` → container `8000`).
- `.env.example`: environment variable template.

## Quick start

1. Create env file:

```bash
cp .env.example .env
```

2. Fill at least:

- `AFC_BASE_URL` (host root **without** `/api`, e.g. `https://afc.example.local`)
- `AFC_USERNAME`
- `AFC_PASSWORD`
- `AFC_VERIFY_SSL` (optional, default `false`)
- `AFC_TIMEOUT` (optional, default `30`)

3. Build and run:

```bash
docker compose up --build -d
```

4. Check logs:

```bash
docker compose logs -f
```

## Endpoint

The server speaks MCP over **streamable-HTTP**:

```
URL:  http://<docker-host>:8010/mcp
```

By default the endpoint is open. You can enable Bearer-token authentication so
only clients presenting a valid token can call the tools (see below).

## Authentication (Bearer token)

Authentication is **optional and disabled by default** (backward compatible).
When enabled, every MCP request must carry an `Authorization: Bearer <token>`
header; requests without a valid token are rejected with `401`.

Tokens are *named* (one per client) and stored in `secrets/.tokens` (git-ignored,
mounted read-write into the container).

1. Create the first token (run on the host or inside the container):

```bash
# on the host (stdlib only, no dependencies needed)
cd afc-mcp
python afc_token_manager.py generate --name "vscode-dev" --description "Laptop VSCode"

# ...or inside the running container
docker compose exec afc-mcp python afc_token_manager.py generate --name "vscode-dev"
```

The command prints the clear-text token **once** — copy it now.

2. Enable auth and (re)start the server:

```bash
# in .env or the shell environment
AFC_AUTH_ENABLED=true

docker compose up -d --build
```

> Safety net: if `AFC_AUTH_ENABLED=true` but no token exists yet, the server
> starts in **LOCKED** mode and refuses every request (`503`) until a token is
> created and the container restarted. This prevents accidentally exposing an
> open endpoint.

Manage tokens with the CLI:

```bash
python afc_token_manager.py list                 # masked preview
python afc_token_manager.py show --name vscode-dev  # reveal a value
python afc_token_manager.py revoke --name vscode-dev
```

Revoking or adding a token requires a container restart to take effect.

> Note: `MCP_HOST` / `MCP_PORT` only control **where the server listens** inside
> the container (`0.0.0.0:8000`, mapped to host `8010`). They are unrelated to
> authentication — they say *where* the server listens, not *who* may call it.

## Integrate with VS Code

VS Code (with GitHub Copilot / agent mode) discovers MCP servers from an `mcp.json` file.

1. Create `.vscode/mcp.json` in your workspace (or add to your user `mcp.json`):

```json
{
  "servers": {
    "afc-mcp": {
      "type": "http",
      "url": "http://localhost:8010/mcp"
    }
  }
}
```

> Replace `localhost` with the Docker host address if the container runs elsewhere.
>
> If authentication is enabled, add the Bearer token as a header:
>
> ```json
> {
>   "servers": {
>     "afc-mcp": {
>       "type": "http",
>       "url": "http://localhost:8010/mcp",
>       "headers": { "Authorization": "Bearer afc_xxxxxxxx" }
>     }
>   }
> }
> ```

2. Open the Command Palette → **MCP: List Servers**, select `afc-mcp` and start it.
3. In the Chat view (Agent mode), the AFC tools become available under the tools picker.

## Integrate with Claude Desktop

Claude Desktop connects to local (stdio) servers by default. To reach this
streamable-HTTP server, bridge it with [`mcp-remote`](https://www.npmjs.com/package/mcp-remote).

Edit `claude_desktop_config.json`:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "afc-mcp": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://localhost:8010/mcp"]
    }
  }
}
```

Restart Claude Desktop; `afc-mcp` appears in the tools menu.

> Alternatively, recent Claude Desktop builds support remote MCP servers directly under
> **Settings → Connectors → Add custom connector** using the same URL.

## Available MCP tools

### Server & system
- `get_server_status` — MCP server reachability/health.
- `get_system_info` — AFC system information.

### Switches & fabrics
- `list_switches`, `get_switch` — switch inventory and per-switch detail (ports, software, tags).
- `list_fabrics`, `get_fabric` — fabric inventory and members.

### Routing & overlay
- `list_vrfs`, `get_vrf` — VRF inventory and detail.
- `get_vrf_bgp_status`, `get_vrf_bgp_summary` — BGP state and summary per VRF.
- `get_vrf_ospf_neighbors`, `get_vrf_ospf_summary` — OSPF neighbors and summary per VRF.
- `list_evpn`, `list_evpn_routes` — EVPN instances and routes.
- `get_vrf_virtual_environment` — virtual environment bound to a VRF.

### Sites & overview
- `list_afc_sites`, `get_afc_site_inventory` — AFC (remote) sites and their inventory.
- `get_network_overview` — aggregated network state snapshot.

### Health
- `list_health_alerts` — active AFC health alerts.
- `run_health_check` — aggregated health (alerts, switch/fabric health, BGP/OSPF
  adjacencies, optional HA + license status).

### Integrations & VMware vCenter/vSphere
- `list_integrations` — all integration packs, their remote servers and connection state.
- `list_vmware_integrations` — vSphere-only: one entry per configured vCenter with
  server address, connection state and fault message.
- `get_vmware_inventory` — VMware hosts with **location** (vCenter, datacenter, cluster,
  domain) and **status** (physical NIC states, VM power breakdown), plus vSwitches,
  Port Groups and VMs. Optional filter by ESXi host name.
- `list_vmware_vms` — flat VM inventory with **power status** and **placement**
  (ESXi host, cluster, datacenter, vCenter), IPs and tags. Optional filters:
  `power_state`, `host_name`.
- `get_vm_attachment` — trace a VM's end-to-end network attachment (vNIC → Port Group →
  vSwitch → host uplink → physical switch/port).

## Notes

- `AFC_BASE_URL` must be the host root **without** `/api`; the client adds the `/api` prefix.
- API authentication uses `POST /api/auth/token` with `X-Auth-Username` and
  `X-Auth-Password` headers; the token is reused and refreshed automatically on `401`.
- The vSphere pack does not expose a per-host power/health field: host status is derived
  from physical NIC states and VM power counts; `vcenter` is the vSphere instance UUID.
