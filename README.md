# MyVectors (draft MVP)

Self-hosted exposure-path inventory with **table + interactive graph**, on-demand DNS/HTTP2/NAT imports, on-demand Device42 integration, and analyst-defined proxy/backend relationships. No scheduled jobs or active scanning.

## Quick start

```bash
docker compose build
docker compose up -d
```

By default bind to `127.0.0.1:42002`. Open `http://127.0.0.1:42002` on the host or tunnel through SSH. For team access, place behind an **authenticated** internal reverse proxy with TLS (the draft app itself does not implement login). Keep backups of the `myvectors-data` volume.

If you use a corporate proxy for builds, pass `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` as Docker build arguments as appropriate for your environment. Outbound Device42 calls use the container's proxy/NO_PROXY configuration.

## Workflow

1. Import `domain-list.xlsx` (columns `RR name`, `Type`, `TTL`, `Value`). Supports A, AAAA, and CNAME; other record types ignored.
2. Import `http2_results.csv` (domain, http_version, http_status, http2_enabled). **HTTP/2=YES denotes protocol exposure, not confirmed CVE exploitability.**
3. Import NAT mapping from Device42 API (preferred) or `ip-natmap.csv` (fallback).
4. Import device/IP associations from Device42's detailed device list API.
5. Add manual `proxies_to`, `routes_to`, or `hosts` relationships for traffic that traverses additional hops. Use verified/suspected/unknown confidence and notes.
6. Explore the table or click **Focus** on an object to view its nearby graph (3 hops). Table entries with Device42 device IDs include a direct link to Device42.

Device42 connector requires `DEVICE42_URL` (HTTPS only; configure using the environment variable) and prompts for Basic auth credentials **on every request**. It never stores passwords in the database or browser storage. TLS verification is enabled by default; supply your internal CA to the container rather than disabling verification in production.

### Device42 API endpoints

- `GET /api/1.0/ipnat/` for standard NAT/Map records.
- `GET /api/1.0/devices/all/` for devices with their IP associations.

Imports use bounded pagination (up to 20 pages of 1000). API response schemas vary by Device42 version; verify import counts and spot-check a few nodes/links in your environment. Importing some very large NAT IP ranges (>1024 addresses) is intentionally skipped and reported. Unsupported mappings are not silently guessed.

## Limitations / safety

- **Draft prototype**: test with anonymized sample data first and ensure a backup before importing real records.
- Not a substitute for patch/version verification. HTTP/2 checks report only externally negotiated protocol.
- Imported data and manual links are additive/upserted; stale entries are not automatically deleted.
- No import automation, no automatic scanning, and no connection to Octosam yet.
- No user login, audit trail, or roles in this MVP. Expose only through a protected internal gateway. File imports are limited to 16MB.
- Device names are joined to IPs reported by D42; shared IPs and reverse proxies may need manual disambiguation.
- NAT direction assumes `Source_IP_Address_Start` is upstream/public and `Target_IP_Address_Start` is downstream/private. Validate this for your Device42 setup.

## Tests

```bash
python -m pip install -r requirements.txt pytest
pytest -q
```
