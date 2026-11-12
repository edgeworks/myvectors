# MyVectors (MVP)

Self-hosted exposure and dependency inventory: **searchable table + interactive graph**, on-demand DNS/NAT imports, Device42 import, and manually documented proxy/backend paths. It is deliberately vulnerability-agnostic: it does not contain a CVE/HTTP2-specific assessment column.

## Run

```bash
docker compose up -d --build
```

Open `http://<server-ip>:42002` from your LAN. The published port binds to `0.0.0.0` by default. **There is no built-in authentication or access control.** Restrict port 42002 with a host/network firewall, ideally use an authenticated HTTPS reverse proxy, and allow only trusted analysts. The Device42 API import and Settings URL are sensitive capabilities; do not expose directly to untrusted users. Back up the `myvectors-data` volume before upgrades or bulk deletion.

If you use a corporate proxy, configure it using a **local `.env` file** beside `compose.yaml` (already ignored by Git). `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` are passed to the Docker build and to Python Requests at runtime. The default local bypass list includes `.local`, `.internal` and private IPv4 networks; add your own internal FQDNs or suffixes using `NO_PROXY`. Keep passwords and internal endpoint details out of this public repository.

Example local `.env` (replace the proxy and internal suffix):

```dotenv
HTTP_PROXY=http://proxy.example.invalid:8080
HTTPS_PROXY=http://proxy.example.invalid:8080
NO_PROXY=localhost,127.0.0.1,::1,.local,.internal,.corp.example,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

## Workflow

1. **Imports → DNS Excel:** import `domain-list.xlsx` with columns `RR name`, `Type`, `TTL`, `Value` (A, AAAA, CNAME supported).
2. **Settings → Device42:** enter your HTTPS Device42 appliance base URL and, if needed, the IP detail URL path template (default: `/admin/rackraj/ipaddress/{id}/`). If your version uses a different route, open a real IP detail page in Device42 and replace its numeric ID with `{id}`. Both values are saved **locally in SQLite**, not GitHub. An optional `DEVICE42_URL` environment variable provides a URL fallback. Credentials are never stored.
3. **Imports → Device42 API:** enter username/password and manually request NAT and device/IP association imports. Use **Import IP links** to retrieve IP inventory IDs via `GET /api/1.0/ips/` and link existing MyVectors IPs to their Device42 detail pages. Only a unique IP-to-record match gets a direct link; overlapping addresses across VRF groups are marked ambiguous. Credentials are used for the request only and are not stored. Alternatively import the existing NAT CSV.
4. **Add connection:** document reverse proxies, load balancers, application routing, and other missing relationships. Use confidence levels and notes.
5. **Explore:** search/filter objects, inspect a selected object, and switch to Graph to trace neighboring relationships. Device42-linked devices have direct links back to Device42.
6. **Delete:** check objects individually (or select all currently filtered rows), then click **Delete selected**, or use the **Remove** button for a single object. A confirmation reports the number of connected relationships that will also be deleted. Deletion is permanent and **re-importing source data may recreate deleted objects**; imported data and manual links are not otherwise modified by the deletion action.

There are **no automatic background imports, active probes, CVE-specific checkers, or scheduled tasks** in this MVP. Source data and analyst assertions are separate; this tool is not evidence that a host is safe or vulnerable.

### Device42 integration

- `GET /api/1.0/ipnat/` for NAT IP/Map data.
- `GET /api/1.0/devices/all/` for devices and their reported IPs.
- `GET /api/1.0/ips/` for IPAM record IDs, used only to enrich existing local IPs with clickable links.

Device42 IP detail-page route formats can vary; verify the configured path by clicking one imported link. If Device42 contains the same IP in multiple VRFs, MyVectors will not pick a record arbitrarily because the local IP key does not include VRF identity. IP link imports do not add new IP objects or change existing relationships.

Device42 versions can vary in API response structure. Import requests are limited to 20 pages of 1,000 records; NAT ranges >1024 addresses are skipped and reported. Validate import counts and NAT direction (`Source_IP_Address_Start` is assumed public/upstream). Links to imported device IDs use the configured Device42 base URL, so changing the appliance URL also refreshes links in the UI.

TLS validation is enabled for Device42 by default. Provide your internal CA to the container if needed instead of disabling verification. Make sure your container's `NO_PROXY` includes the internal Device42 host where a proxy is configured.

## Tests

```bash
python -m pip install -r requirements.txt pytest
pytest -q
```

Existing SQLite volumes migrate automatically: an additional `settings` table is created. Previously imported HTTP/2 observations, if any, remain in old domain metadata but there is no specialized HTTP/2 importer or column in the new GUI. Export/backup the database if these historic observations matter. A deletion removes associated edges, not other objects.