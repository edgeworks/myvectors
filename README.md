# MyVectors (MVP)

Self-hosted exposure and dependency inventory: **searchable table + interactive graph**, on-demand DNS/NAT imports, Device42 import, and manually documented proxy/backend paths. It is deliberately vulnerability-agnostic: it does not contain a CVE/HTTP2-specific assessment column.

## Run

```bash
docker compose up -d --build
```

Open `http://127.0.0.1:42002` on the Docker host or use an SSH tunnel. The container binds only to localhost by default. **There is no built-in authentication or access control.** For team access, deploy behind an authenticated HTTPS reverse proxy and restrict access to trusted analysts. The Device42 API import and Settings URL are sensitive capabilities; do not expose directly to untrusted users. Back up the `myvectors-data` volume before upgrades or bulk deletion.

## Workflow

1. **Imports → DNS Excel:** import `domain-list.xlsx` with columns `RR name`, `Type`, `TTL`, `Value` (A, AAAA, CNAME supported).
2. **Settings → Device42:** enter your HTTPS Device42 appliance base URL. Saved **locally in the SQLite database**; not committed to GitHub. An optional `DEVICE42_URL` environment variable provides a fallback until a setting is saved. Clear the GUI URL to disable it if no fallback is set. Only store the URL, not credentials.
3. **Imports → Device42 API:** enter username/password and manually request NAT and device-IP imports. Credentials are passed to the backend for that request and are not stored. Alternatively import the existing NAT CSV.
4. **Add connection:** document reverse proxies, load balancers, application routing, and other missing relationships. Use confidence levels and notes.
5. **Explore:** search/filter objects, inspect a selected object, and switch to Graph to trace neighboring relationships. Device42-linked devices have direct links back to Device42.
6. **Delete:** check objects individually (or select all currently filtered rows), then click **Delete selected**, or use the **Remove** button for a single object. A confirmation reports the number of connected relationships that will also be deleted. Deletion is permanent and **re-importing source data may recreate deleted objects**; imported data and manual links are not otherwise modified by the deletion action.

There are **no automatic background imports, active probes, CVE-specific checkers, or scheduled tasks** in this MVP. Source data and analyst assertions are separate; this tool is not evidence that a host is safe or vulnerable.

### Device42 integration

- `GET /api/1.0/ipnat/` for NAT IP/Map data.
- `GET /api/1.0/devices/all/` for devices and their reported IPs.

Device42 versions can vary in API response structure. Import requests are limited to 20 pages of 1,000 records; NAT ranges >1024 addresses are skipped and reported. Validate import counts and NAT direction (`Source_IP_Address_Start` is assumed public/upstream). Links to imported device IDs use the configured Device42 base URL, so changing the appliance URL also refreshes links in the UI.

TLS validation is enabled for Device42 by default. Provide your internal CA to the container if needed instead of disabling verification. Make sure your container's `NO_PROXY` includes the internal Device42 host where a proxy is configured.

## Tests

```bash
python -m pip install -r requirements.txt pytest
pytest -q
```

Existing SQLite volumes migrate automatically: an additional `settings` table is created. Previously imported HTTP/2 observations, if any, remain in old domain metadata but there is no specialized HTTP/2 importer or column in the new GUI. Export/backup the database if these historic observations matter. A deletion removes associated edges, not other objects.