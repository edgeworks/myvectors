"""MyVectors: on-demand exposure-path inventory (no automatic scanning)."""
import csv
import io
import ipaddress
import json
import os
import re
import sqlite3
from uuid import uuid4
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

import requests
from flask import Flask, jsonify, request, send_from_directory
from openpyxl import load_workbook

BASE = Path(__file__).resolve().parent
DB_PATH = os.environ.get('MYVECTORS_DB', str(BASE / 'data' / 'myvectors.sqlite3'))
D42_URL = os.environ.get('DEVICE42_URL', '').rstrip('/')  # optional fallback; GUI value lives in SQLite
D42_VERIFY_TLS = os.environ.get('D42_VERIFY_TLS', 'true').lower() == 'true'
DEFAULT_D42_IP_PATH = '/admin/rackraj/ipaddress/{id}/'
KINDS = {'domain', 'ip', 'device', 'service'}
RELATIONS = {'resolves_to', 'nat_to', 'belongs_to', 'proxies_to', 'routes_to', 'hosts', 'connects_to'}

app = Flask(__name__, static_folder='static')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def connect():
    path = Path(app.config.get('DB_PATH', DB_PATH))
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.executescript('''
      CREATE TABLE IF NOT EXISTS nodes (
        id INTEGER PRIMARY KEY, kind TEXT NOT NULL, key TEXT NOT NULL,
        label TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{}',
        d42_url TEXT NOT NULL DEFAULT '', updated TEXT NOT NULL,
        UNIQUE(kind, key));
      CREATE TABLE IF NOT EXISTS edges (
        id INTEGER PRIMARY KEY, src INTEGER NOT NULL REFERENCES nodes(id),
        dst INTEGER NOT NULL REFERENCES nodes(id), relation TEXT NOT NULL,
        origin TEXT NOT NULL, ref TEXT NOT NULL DEFAULT '',
        confidence TEXT NOT NULL DEFAULT 'imported',
        note TEXT NOT NULL DEFAULT '', details TEXT NOT NULL DEFAULT '{}',
        updated TEXT NOT NULL,
        UNIQUE(src, dst, relation, origin, ref));
      CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS d42_ip_runs (
        run_id TEXT PRIMARY KEY, next_offset INTEGER NOT NULL DEFAULT 0,
        created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
      CREATE TABLE IF NOT EXISTS d42_ip_candidates (
        run_id TEXT NOT NULL, ip TEXT NOT NULL, record_id TEXT NOT NULL,
        PRIMARY KEY(run_id, ip, record_id));
      CREATE TABLE IF NOT EXISTS d42_ip_device_candidates (
        run_id TEXT NOT NULL, ip TEXT NOT NULL, record_id TEXT NOT NULL,
        device_id TEXT NOT NULL, device_name TEXT NOT NULL,
        device_type TEXT NOT NULL DEFAULT '',
        PRIMARY KEY(run_id,ip,record_id,device_id));
      CREATE TABLE IF NOT EXISTS d42_ip_targets (
        run_id TEXT NOT NULL, seq INTEGER NOT NULL, ip TEXT NOT NULL,
        PRIMARY KEY(run_id,ip), UNIQUE(run_id,seq));
      CREATE INDEX IF NOT EXISTS d42_ip_candidates_run ON d42_ip_candidates(run_id);
      CREATE INDEX IF NOT EXISTS edges_src ON edges(src);
      CREATE INDEX IF NOT EXISTS edges_dst ON edges(dst);
    ''')
    return db


def validate_d42_url(value):
    if not isinstance(value, str):
        raise ValueError('Device42 URL must be a string')
    value = value.strip().rstrip('/')
    if value and any(ord(ch) < 33 for ch in value):
        raise ValueError('Device42 URL contains invalid whitespace or control characters')
    if not value:
        return ''
    if len(value) > 512:
        raise ValueError('Device42 URL is too long')
    parsed = urlparse(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or
            parsed.password or parsed.path or parsed.query or parsed.fragment):
        raise ValueError('Enter an HTTPS Device42 base URL without credentials, path, or query')
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError('Invalid Device42 port') from exc
    return value


def configured_d42_url(db=None):
    if db is None:
        with connect() as conn:
            return configured_d42_url(conn)
    item = db.execute('SELECT value FROM settings WHERE key=?', ('device42_url',)).fetchone()
    return item['value'] if item else D42_URL


def validate_d42_ip_path(value):
    if not isinstance(value, str) or not value:
        raise ValueError('Device42 IP detail path is required')
    if (len(value) > 255 or not value.startswith('/') or value.startswith('//') or
            value.count('{id}') != 1 or not re.fullmatch(r'[A-Za-z0-9/_{}.-]+', value) or
            '..' in value):
        raise ValueError('Enter a relative path such as /admin/rackraj/ipaddress/{id}/')
    return value


def configured_d42_ip_path(db=None):
    if db is None:
        with connect() as conn:
            return configured_d42_ip_path(conn)
    item = db.execute('SELECT value FROM settings WHERE key=?', ('device42_ip_path',)).fetchone()
    return item['value'] if item else DEFAULT_D42_IP_PATH


def device42_ip_link(base, ip_id, path):
    if base and str(ip_id).isdigit():
        return base + validate_d42_ip_path(path).replace('{id}', quote(str(ip_id)))
    return ''


def device42_link(base, device_id):
    return base + '/admin/rackraj/device/' + quote(str(device_id)) + '/' if base and str(device_id).isdigit() else ''


def normalize(kind, key):
    value = str(key or '').strip()
    if kind == 'domain':
        return value.rstrip('.').lower()
    if kind == 'ip':
        return str(ipaddress.ip_address(value))
    return value.lower()


def node(db, kind, key, label=None, details=None, d42_url=''):
    if kind not in KINDS:
        raise ValueError('Invalid node kind')
    norm = normalize(kind, key)
    if not norm or len(norm) > 255:
        raise ValueError('Invalid node key')
    record = db.execute('SELECT * FROM nodes WHERE kind=? AND key=?', (kind, norm)).fetchone()
    existing = json.loads(record['details']) if record else {}
    existing.update(details or {})
    title = label or (record['label'] if record else str(key).strip())
    d42_link = d42_url or (record['d42_url'] if record else '')
    db.execute('''INSERT INTO nodes(kind,key,label,details,d42_url,updated)
      VALUES(?,?,?,?,?,?) ON CONFLICT(kind,key) DO UPDATE SET
      label=excluded.label,details=excluded.details,d42_url=excluded.d42_url,
      updated=excluded.updated''',
      (kind, norm, title, json.dumps(existing), d42_link, now()))
    return db.execute('SELECT id FROM nodes WHERE kind=? AND key=?', (kind, norm)).fetchone()['id']


def edge(db, src, dst, relation, origin, ref='', confidence='imported', note='', details=None):
    if relation not in RELATIONS:
        raise ValueError('Invalid relationship')
    db.execute('''INSERT INTO edges(src,dst,relation,origin,ref,confidence,note,details,updated)
      VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(src,dst,relation,origin,ref)
      DO UPDATE SET confidence=excluded.confidence,note=excluded.note,
      details=excluded.details,updated=excluded.updated''',
      (src, dst, relation, origin, str(ref), confidence, note,
       json.dumps(details or {}), now()))


def canon(row):
    return {re.sub(r'[^a-z0-9]', '', str(k).lower()): v for k, v in row.items()}


def val(row, *names):
    d = canon(row)
    for name in names:
        found = d.get(re.sub(r'[^a-z0-9]', '', name.lower()))
        if found is not None and str(found).strip():
            return str(found).strip()
    return ''


def import_dns(db, rows):
    count = 0
    for r in rows:
        rr = val(r, 'RR name')
        typ = val(r, 'Type').upper()
        value = val(r, 'Value')
        if not rr or not value or typ not in ('A', 'AAAA', 'CNAME'):
            continue
        try:
            src = node(db, 'domain', rr)
            if typ == 'CNAME':
                dst = node(db, 'domain', value)
            else:
                dst = node(db, 'ip', value)
            edge(db, src, dst, 'resolves_to', 'dns', ref=typ, details={'record_type': typ, 'ttl': val(r, 'TTL')})
            count += 1
        except ValueError:
            continue
    return count


def ip_range(begin, end, ceiling=1024):
    first = ipaddress.ip_address(begin)
    last = ipaddress.ip_address(end or begin)
    if first.version != last.version or int(last) < int(first):
        raise ValueError('Invalid NAT IP range')
    size = int(last) - int(first) + 1
    if size > ceiling:
        raise ValueError('NAT IP range exceeds 1024 addresses; review manually')
    return [str(ipaddress.ip_address(int(first) + i)) for i in range(size)]


def import_nat(db, rows, diagnostics=None):
    count, skipped = 0, 0
    reasons = {}
    fields = set()
    def skip(reason):
        nonlocal skipped
        skipped += 1
        reasons[reason] = reasons.get(reason, 0) + 1
    for r in rows:
        if not isinstance(r, dict):
            skip('non_object_record')
            continue
        fields.update(str(k)[:80] for k in r if k != '__from_api')
        src = val(r, 'Source_IP_Address_Start', 'source_ip_start', 'source_address_start', 'source_start', 'ip_address_from')
        dst = val(r, 'Target_IP_Address_Start', 'target_ip_start', 'target_address_start', 'target_start', 'ip_address_to')
        if not src or not dst:
            skip('missing_source_or_target_ip')
            continue
        try:
            sources = ip_range(src, val(r, 'Source_IP_Address_End', 'ip_address_from_end'))
            targets = ip_range(dst, val(r, 'Target_IP_Address_End', 'ip_address_to_end'))
        except ValueError:
            skip('invalid_ip_or_range_over_1024')
            continue
        if len(targets) not in (1, len(sources)):
            skip('incompatible_source_target_ranges')
            continue
        rule = val(r, 'Name') or f'{src}->{dst}'
        info = {'protocol': val(r, 'Protocol'), 'source_port': val(r, 'Source_Port_Start'),
                'source_port_end': val(r, 'Source_Port_End'), 'target_port': val(r, 'Target_Port_Start'),
                'target_port_end': val(r, 'Target_Port_End'), 'rule': rule}
        for i, public in enumerate(sources):
            a = node(db, 'ip', public)
            b = node(db, 'ip', targets[min(i, len(targets) - 1)])
            edge(db, a, b, 'nat_to', 'd42_nat' if val(r, '__from_api') else 'nat_csv',
                 ref=rule + ':' + json.dumps(info, sort_keys=True),
                 note=val(r, 'Notes'), details=info)
            count += 1
    if diagnostics is not None:
        diagnostics['skip_reasons'] = reasons
        diagnostics['api_field_names'] = sorted(fields)[:80]
    return count, skipped


def extract_rows(payload, names):
    # Device42 versions differ: some return {"Devices": [...]}, others
    # {"Devices": {"devices": [...], "total_count": ...}}.
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        normalized = canon(payload)
        keys = tuple(names) + ('results', 'data', 'items')
        for name in keys:
            found = normalized.get(re.sub(r'[^a-z0-9]', '', name.lower()))
            if isinstance(found, list):
                return found
            if isinstance(found, dict):
                nested = canon(found)
                for nested_name in keys:
                    rows = nested.get(re.sub(r'[^a-z0-9]', '', nested_name.lower()))
                    if isinstance(rows, list):
                        return rows
    raise ValueError('Unrecognized Device42 response shape; no changes were imported')


def d42_get(path, credentials, params):
    base = validate_d42_url(configured_d42_url())
    if not base:
        raise ValueError('Set the Device42 URL under Settings first')
    response = requests.get(base + path, params=params, auth=credentials,
                            verify=D42_VERIFY_TLS, timeout=(8, 35),
                            allow_redirects=False,
                            headers={'Accept': 'application/json'})
    status = response.status_code
    content_type = response.headers.get('Content-Type', '').split(';', 1)[0][:80]
    if 300 <= status < 400:
        raise ValueError(
            f'Device42 API {path} returned HTTP {status} redirect instead of JSON. '
            'Check credentials, SSO/reverse proxy and endpoint access.')
    if status >= 400:
        raise ValueError(
            f'Device42 API {path} returned HTTP {status} '
            f'({content_type or "unknown content type"}). '
            'Check API permissions, endpoint and proxy configuration.')
    try:
        payload = response.json()
    except ValueError as exc:
        raise ValueError(
            f'Device42 API {path} returned HTTP {status} '
            f'({content_type or "unknown content type"}) instead of JSON. '
            'Check API authentication, SSO/proxy interception or endpoint availability.'
        ) from exc
    if not isinstance(payload, (dict, list)):
        raise ValueError(f'Device42 API {path} returned an unexpected JSON type')
    return payload



def d42_post(path, credentials, form):
    base = validate_d42_url(configured_d42_url())
    if not base:
        raise ValueError('Set the Device42 URL under Settings first')
    response = requests.post(base + path, data=form, auth=credentials,
                             verify=D42_VERIFY_TLS, timeout=(8, 35),
                             allow_redirects=False,
                             headers={'Accept': 'application/json'})
    status = response.status_code
    if 300 <= status < 400:
        raise ValueError(f'Device42 DOQL returned HTTP {status} redirect instead of JSON')
    if status >= 400:
        raise ValueError(f'Device42 DOQL returned HTTP {status}; check query permissions and schema')
    try:
        payload = response.json()
    except ValueError as exc:
        raise ValueError('Device42 DOQL returned non-JSON data; verify output_type=json') from exc
    if not isinstance(payload, (dict, list)):
        raise ValueError('Unexpected Device42 DOQL response format')
    return payload



def d42_pages(path, names, credentials):
    all_rows = []
    for page in range(20):  # deliberate bound: max 20,000 records per operation
        batch = extract_rows(d42_get(path, credentials,
                          {'limit': 1000, 'offset': page * 1000}), names)
        all_rows.extend(batch)
        if len(batch) < 1000:
            break
    else:
        raise ValueError('Device42 response exceeded the 20,000 record import cap')
    return all_rows


def device_ips(raw):
    values = raw if isinstance(raw, list) else [raw] if raw else []
    result = []
    for item in values:
        if isinstance(item, dict):
            candidate = val(item, 'ip', 'ip_address', 'address')
        else:
            candidate = str(item)
        try:
            result.append(str(ipaddress.ip_address(candidate)))
        except ValueError:
            pass
    return result


def import_devices(db, rows):
    count = 0
    for r in rows:
        if not isinstance(r, dict):
            continue
        name = val(r, 'name')
        if not name:
            continue
        device_id = val(r, 'device_id', 'id')
        link = device42_link(configured_d42_url(db), device_id)
        device = node(db, 'device', name, label=name,
                      details={'d42_id': device_id, 'os': val(r, 'os'),
                               'type': val(r, 'type')}, d42_url=link)
        for ip in device_ips(r.get('ip_addresses') or r.get('ips') or r.get('ip_address')):
            addr = node(db, 'ip', ip)
            edge(db, addr, device, 'belongs_to', 'd42_devices', ref=device_id or name)
            count += 1
    return count


def response_state():
    with connect() as db:
        nodes = [dict(x) for x in db.execute('SELECT * FROM nodes ORDER BY kind,label')]
        edges = [dict(x) for x in db.execute('SELECT * FROM edges ORDER BY id')]
        base = configured_d42_url(db)
        ip_path = configured_d42_ip_path(db)
    for x in nodes + edges:
        x['details'] = json.loads(x['details'])
    for x in nodes:
        if x['kind'] == 'device' and x['details'].get('d42_id'):
            x['d42_url'] = device42_link(base, x['details']['d42_id'])
        if x['kind'] == 'ip':
            x['d42_url'] = device42_ip_link(base, x['details'].get('d42_ip_id'), ip_path)
            # Build links at response time so changing the GUI URL updates them.
            for candidate in x['details'].get('d42_devices', []):
                candidate['url'] = device42_link(base, candidate.get('id', ''))
    return {'nodes': nodes, 'edges': edges}


@app.get('/')
def home():
    return send_from_directory('static', 'index.html')


@app.get('/api/state')
def state():
    return jsonify(response_state())


@app.get('/api/settings')
def get_settings():
    return jsonify(device42_url=configured_d42_url(), device42_ip_path=configured_d42_ip_path())


@app.put('/api/settings')
def save_settings():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error='Expected JSON object'), 400
    try:
        value = validate_d42_url(data.get('device42_url'))
        path = validate_d42_ip_path(data.get('device42_ip_path', configured_d42_ip_path()))
        with connect() as db:
            db.execute('INSERT INTO settings(key,value) VALUES(?,?) '
                       'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                       ('device42_url', value))
            db.execute('INSERT INTO settings(key,value) VALUES(?,?) '
                       'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                       ('device42_ip_path', path))
        return jsonify(device42_url=value, device42_ip_path=path)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400


@app.post('/api/nodes/delete')
def delete_nodes():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error='Expected JSON object'), 400
    ids = data.get('ids')
    if (not isinstance(ids, list) or not ids or len(ids) > 10000 or
            any(type(x) is not int or x <= 0 for x in ids)):
        return jsonify(error='Provide 1-10000 valid integer IDs'), 400
    ids = list(set(ids))
    with connect() as db:
        existing = {row['id'] for row in db.execute('SELECT id FROM nodes')}
        if not set(ids).issubset(existing):
            return jsonify(error='One or more objects no longer exist; refresh the list'), 404
        before = db.execute('SELECT COUNT(*) FROM edges').fetchone()[0]
        db.executemany('DELETE FROM edges WHERE src=? OR dst=?', [(i, i) for i in ids])
        after = db.execute('SELECT COUNT(*) FROM edges').fetchone()[0]
        db.executemany('DELETE FROM nodes WHERE id=?', [(i,) for i in ids])
    return jsonify(deleted=len(ids), connections_deleted=before-after)


@app.post('/api/import/<kind>')
def file_import(kind):
    if kind not in ('dns', 'nat'):
        return jsonify(error='Invalid import type'), 400
    upload = request.files.get('file')
    if not upload:
        return jsonify(error='File missing'), 400
    try:
        if kind == 'dns':
            wb = load_workbook(upload.stream, read_only=True, data_only=True)
            try:
                sheet = wb.active
                values = sheet.iter_rows(values_only=True)
                headings = next(values)
                rows = (dict(zip(headings, row)) for row in values)
                with connect() as db:
                    count = import_dns(db, rows)
            finally:
                wb.close()
            return jsonify(imported=count)
        content = upload.stream.read().decode('utf-8-sig')
        rows = csv.DictReader(io.StringIO(content))
        diagnostics = {}
        with connect() as db:
            count, skipped = import_nat(db, rows, diagnostics=diagnostics)
        return jsonify(imported=count, skipped=skipped, **diagnostics)
    except (ValueError, UnicodeError, OSError, StopIteration, KeyError) as exc:
        return jsonify(error=str(exc)), 400


@app.post('/api/nodes')
def create_node():
    data = request.get_json(silent=True) or {}
    try:
        with connect() as db:
            key = node(db, data.get('kind'), data.get('key'), label=data.get('label'),
                       details={'note': str(data.get('note', ''))[:2000]})
        return jsonify(id=key)
    except (ValueError, TypeError) as exc:
        return jsonify(error=str(exc)), 400


@app.post('/api/connections')
def create_connection():
    data = request.get_json(silent=True) or {}
    try:
        if data.get('confidence') not in ('verified', 'suspected', 'unknown'):
            raise ValueError('Invalid confidence')
        with connect() as db:
            src = node(db, data['from_kind'], data['from_key'])
            dst = node(db, data['to_kind'], data['to_key'])
            edge(db, src, dst, data['relation'], 'manual',
                 confidence=data['confidence'], note=str(data.get('note', ''))[:2000])
        return jsonify(ok=True)
    except (ValueError, TypeError, KeyError) as exc:
        return jsonify(error=str(exc)), 400


# Keep individual Device42 calls small. The default 1000-record IP API response
# has been observed to exceed Gunicorn's worker timeout on some appliances.
D42_PAGE_SIZES = {'devices': 50, 'ip_links': 25}
D42_MAX_OFFSET = 100000


def d42_page_count(payload):
    """Optional total count, where provided by Device42."""
    if isinstance(payload, dict):
        for obj in (payload, *[v for v in payload.values() if isinstance(v, dict)]):
            for key in ('total_count', 'total', 'count'):
                value = obj.get(key)
                if value is not None and str(value).isdigit():
                    return int(value)
    return None


def start_nat_ip_run(db):
    """Take a stable snapshot of unique NAT endpoint addresses only."""
    db.execute("DELETE FROM d42_ip_candidates WHERE run_id IN "
               "(SELECT run_id FROM d42_ip_runs WHERE created < datetime('now','-1 day'))")
    db.execute("DELETE FROM d42_ip_device_candidates WHERE run_id IN "
               "(SELECT run_id FROM d42_ip_runs WHERE created < datetime('now','-1 day'))")
    db.execute("DELETE FROM d42_ip_targets WHERE run_id IN "
               "(SELECT run_id FROM d42_ip_runs WHERE created < datetime('now','-1 day'))")
    db.execute("DELETE FROM d42_ip_runs WHERE created < datetime('now','-1 day')")
    ips = [r['key'] for r in db.execute("""
        SELECT DISTINCT n.key FROM nodes AS n
        WHERE n.kind='ip' AND n.id IN (
            SELECT src FROM edges WHERE relation='nat_to' AND origin IN ('d42_nat','nat_csv')
            UNION
            SELECT dst FROM edges WHERE relation='nat_to' AND origin IN ('d42_nat','nat_csv')
        ) ORDER BY n.key
    """)]
    if not ips:
        raise ValueError('No NAT IP endpoints found. Import NAT data first.')
    if len(ips) > D42_MAX_OFFSET:
        raise ValueError('Too many NAT IP endpoints for one import')
    run_id = uuid4().hex
    db.execute('INSERT INTO d42_ip_runs(run_id,next_offset) VALUES(?,0)', (run_id,))
    db.executemany('INSERT INTO d42_ip_targets(run_id,seq,ip) VALUES(?,?,?)',
                   ((run_id, i, address) for i, address in enumerate(ips)))
    return run_id, len(ips)


def nat_ip_page(db, run_id, offset, limit):
    if not isinstance(run_id, str) or not re.fullmatch(r'[0-9a-f]{32}', run_id):
        raise ValueError('Invalid IP import session; restart')
    run = db.execute('SELECT next_offset FROM d42_ip_runs WHERE run_id=?', (run_id,)).fetchone()
    if not run or run['next_offset'] != offset:
        raise ValueError('IP import session expired or out of order; restart')
    total = db.execute('SELECT COUNT(*) FROM d42_ip_targets WHERE run_id=?', (run_id,)).fetchone()[0]
    ips = [row['ip'] for row in db.execute(
        'SELECT ip FROM d42_ip_targets WHERE run_id=? ORDER BY seq LIMIT ? OFFSET ?',
        (run_id, limit, offset))]
    if not ips:
        raise ValueError('No more NAT IPs in this import session')
    return ips, total


def d42_nat_ip_query(credentials, ips):
    """Read-only DOQL; input addresses normalized with ipaddress, never raw SQL."""
    if not ips:
        return []
    normalized = [str(ipaddress.ip_address(ip)) for ip in ips]
    quoted = ','.join("'" + ip + "'" for ip in normalized)
    # This is a many-to-many association. A single IP may have zero, one,
    # or several D42 devices; a device may also represent a cluster.
    query = ('SELECT ip.ip_address AS ip_address, '
             'ip.ipaddress_pk AS ipaddress_pk, '
             'dev.device_pk AS device_pk, '
             'dev.name AS device_name, dev.type AS device_type '
             'FROM view_ipaddress_v1 ip '
             'LEFT JOIN view_ipaddress_device_v2 assoc '
             'ON assoc.ipaddress_fk = ip.ipaddress_pk '
             'LEFT JOIN view_device_v1 dev ON dev.device_pk = assoc.device_fk '
             'WHERE ip.ip_address IN (' + quoted + ')')
    payload = d42_post('/services/data/v1.0/query/', credentials,
                       {'query': query, 'output_type': 'json'})
    if isinstance(payload, list):
        return payload
    return extract_rows(payload, ('data', 'rows', 'results', 'items'))


def stage_nat_ip_matches(db, run_id, offset, ips, rows):
    """Stage exact D42 IP and its zero/many device associations, safely."""
    requested = set(ips)
    validated = []
    devices = []
    fields = set()
    for record in rows:
        if not isinstance(record, dict):
            raise ValueError('Unexpected DOQL record type; no mappings changed')
        fields.update(str(k)[:60] for k in record)
        address = val(record, 'ip_address')
        record_id = val(record, 'ipaddress_pk')
        if not address or not record_id.isdecimal():
            raise ValueError('Unexpected DOQL fields: ' + ', '.join(sorted(fields)[:15]))
        try:
            ip = normalize('ip', address)
        except ValueError as exc:
            raise ValueError('Invalid IP returned by Device42 DOQL') from exc
        if ip not in requested:
            raise ValueError('DOQL returned an IP outside requested NAT addresses; import stopped')
        validated.append((run_id, ip, record_id))
        device_id = val(record, 'device_pk')
        device_name = val(record, 'device_name')
        device_type = val(record, 'device_type')
        if device_id or device_name:
            if not device_id.isdecimal() or not device_name:
                raise ValueError('Incomplete Device42 device association for an IP; no mappings changed')
            devices.append((run_id, ip, record_id, device_id,
                            device_name[:255], device_type[:100]))
    db.executemany('INSERT OR IGNORE INTO d42_ip_candidates(run_id,ip,record_id) VALUES(?,?,?)',
                   validated)
    db.executemany('INSERT OR REPLACE INTO d42_ip_device_candidates '
                   '(run_id,ip,record_id,device_id,device_name,device_type) '
                   'VALUES(?,?,?,?,?,?)', devices)
    db.execute('UPDATE d42_ip_runs SET next_offset=? WHERE run_id=?',
               (offset + len(ips), run_id))
    return len(validated)


def finish_ip_run(db, run_id):
    """Commit a complete NAT-IP snapshot, preserving zero/one/many D42 associations."""
    mapping = {}
    for item in db.execute('SELECT ip,record_id FROM d42_ip_candidates WHERE run_id=?',
                           (run_id,)):
        mapping.setdefault(item['ip'], set()).add(item['record_id'])
    device_by_ip = {}
    for item in db.execute('SELECT * FROM d42_ip_device_candidates WHERE run_id=?', (run_id,)):
        device_by_ip.setdefault(item['ip'], {})[item['device_id']] = {
            'id': item['device_id'], 'name': item['device_name'],
            'type': item['device_type'], 'ip_record_id': item['record_id']}
    matched = ambiguous = unassigned = multi_device = mapped_device = 0
    items = db.execute("""
        SELECT n.id,n.key,n.details FROM nodes n
        JOIN d42_ip_targets t ON n.key=t.ip AND t.run_id=?
        WHERE n.kind='ip' ORDER BY t.seq
    """, (run_id,)).fetchall()
    unchanged = not mapping
    if not unchanged:
        # Remove only relations previously created by this exact enrichment,
        # never manual relationships or those from the device inventory import.
        for item in items:
            db.execute("DELETE FROM edges WHERE src=? AND relation='belongs_to' "
                       "AND origin='d42_ip_assoc'", (item['id'],))
        for item in items:
            details = json.loads(item['details'])
            for key in ('d42_ip_id', 'd42_ip_status', 'd42_ip_match_count',
                        'd42_devices', 'd42_device_status'):
                details.pop(key, None)
            ip_ids = mapping.get(item['key'], set())
            candidates = sorted(device_by_ip.get(item['key'], {}).values(),
                                key=lambda c: (c['name'].lower(), c['id']))
            details['d42_devices'] = candidates
            if len(ip_ids) == 1:
                details['d42_ip_id'] = next(iter(ip_ids))
                matched += 1
            elif len(ip_ids) > 1:
                details['d42_ip_status'] = 'ambiguous'
                details['d42_ip_match_count'] = len(ip_ids)
                ambiguous += 1

            if not ip_ids:
                details['d42_device_status'] = 'ip_not_found'
            elif len(ip_ids) > 1:
                details['d42_device_status'] = 'ambiguous_ip'
            elif not candidates:
                details['d42_device_status'] = 'unassigned'
                unassigned += 1
            elif len(candidates) > 1:
                details['d42_device_status'] = 'multiple'
                multi_device += 1
            elif 'cluster' in candidates[0]['type'].lower():
                details['d42_device_status'] = 'cluster'
            else:
                details['d42_device_status'] = 'single'
            if candidates:
                mapped_device += 1
            db.execute('UPDATE nodes SET details=?,updated=? WHERE id=?',
                       (json.dumps(details), now(), item['id']))
            # For ambiguous IPs across VRFs, the device is not safely tied to
            # this IP node. Display the candidates but do not assert graph edges.
            if len(ip_ids) == 1:
                for candidate in candidates:
                    device = node(db, 'device', 'd42:' + candidate['id'],
                                  label=candidate['name'],
                                  details={'d42_id': candidate['id'],
                                           'type': candidate['type'],
                                           'source': 'd42_ip_assoc'})
                    edge(db, item['id'], device, 'belongs_to', 'd42_ip_assoc',
                         ref=next(iter(ip_ids)) + ':' + candidate['id'],
                         note='Device42 IP association; not a verified Octosam identity')
    for table in ('d42_ip_device_candidates', 'd42_ip_candidates',
                  'd42_ip_targets', 'd42_ip_runs'):
        db.execute('DELETE FROM ' + table + ' WHERE run_id=?', (run_id,))
    return {'linked': matched, 'ambiguous': ambiguous,
            'not_found': len(items)-matched-ambiguous,
            'ips_in_myvectors': len(items), 'no_matches_preserved': unchanged,
            'with_device_candidates': mapped_device,
            'multiple_device_candidates': multi_device,
            'unassigned_device': unassigned}


@app.post('/api/d42/<kind>/page')
def device42_import_page(kind):
    if kind not in D42_PAGE_SIZES:
        return jsonify(error='Invalid paged import type'), 400
    data = request.get_json(silent=True) or {}
    username, password = data.get('username', ''), data.get('password', '')
    offset = data.get('offset', 0)
    if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
        return jsonify(error='Device42 credentials are required'), 400
    if type(offset) is not int or offset < 0 or offset > D42_MAX_OFFSET:
        return jsonify(error='Invalid page offset'), 400
    limit = D42_PAGE_SIZES[kind]
    try:
        if kind == 'ip_links':
            # Use only NAT endpoints; no GET /ips/ inventory crawl.
            with connect() as db:
                if offset == 0:
                    run_id, count = start_nat_ip_run(db)
                else:
                    run_id = data.get('run_id')
                ips, total = nat_ip_page(db, run_id, offset, limit)
            rows = d42_nat_ip_query((username, password), ips)
            next_offset = offset + len(ips)
            done = next_offset >= total
            with connect() as db:
                # Checkpoint again in case another request advanced the session.
                check, count = nat_ip_page(db, run_id, offset, limit)
                if check != ips or count != total:
                    raise ValueError('IP import session changed; restart the import')
                found = stage_nat_ip_matches(db, run_id, offset, ips, rows)
                result = {'run_id': run_id, 'received': len(ips), 'matches_received': found,
                          'next_offset': next_offset, 'total_count': total, 'done': done}
                if done:
                    result.update(finish_ip_run(db, run_id))
            return jsonify(result)
        path = '/api/1.0/devices/all/'
        payload = d42_get(path, (username, password), {'limit': limit, 'offset': offset})
        batch = extract_rows(payload, ('devices',))
        if len(batch) > limit:
            raise ValueError('Device42 ignored the requested device page size')
        total = d42_page_count(payload)
        next_offset = offset + len(batch)
        if next_offset > D42_MAX_OFFSET:
            raise ValueError('Device42 device import reached maximum offset')
        done = next_offset >= total if total is not None else len(batch) < limit
        if not batch and total is not None and next_offset < total:
            raise ValueError('Empty Device42 device page before total_count reached')
        with connect() as db:
            imported = import_devices(db, batch)
        return jsonify(received=len(batch),next_offset=next_offset,done=done,
                       total_count=total, imported=imported)
    except requests.exceptions.SSLError:
        return jsonify(error='Device42 TLS validation failed; check CA chain/proxy'), 502
    except requests.Timeout:
        return jsonify(error='Device42 did not respond to this targeted request in time'), 504
    except requests.RequestException as exc:
        return jsonify(error=f'Device42 request failed: {type(exc).__name__}'), 502
    except ValueError as exc:
        return jsonify(error=str(exc)), 502



@app.post('/api/d42/<kind>')
def device42_import(kind):
    if kind != 'nat':
        return jsonify(error='Invalid Device42 import type'), 400
    data = request.get_json(silent=True) or {}
    username, password = data.get('username', ''), data.get('password', '')
    if not username or not password:
        return jsonify(error='Credentials are required'), 400
    try:
        credentials = (username, password)
        if kind == 'nat':
            rows = d42_pages('/api/1.0/ipnat/', ('ipnats', 'ipnat', 'nat'), credentials)
            for r in rows:
                if isinstance(r, dict):
                    r['__from_api'] = True
            diagnostics = {}
            with connect() as db:
                count, skipped = import_nat(db, rows, diagnostics=diagnostics)
            return jsonify(imported=count, skipped=skipped, records_received=len(rows), **diagnostics)
    except requests.exceptions.SSLError as exc:
        # Return only the TLS verifier reason, not untrusted upstream bodies or credentials.
        message = str(exc)
        match = re.search(r'certificate verify failed:\s*(.*?)(?:\s*\(_ssl\.c:|\)\))', message, re.I)
        reason = match.group(1).strip() if match else 'Unable to verify the Device42 TLS certificate'
        return jsonify(error=f'Device42 SSL verification failed: {reason[:350]}'), 502
    except (requests.RequestException, ValueError) as exc:
        # Avoid returning upstream response bodies (may contain sensitive data).
        return jsonify(error=f'Device42 import failed: {type(exc).__name__}: {str(exc)[:180]}'), 502


@app.get('/api/export')
def export():
    return jsonify(response_state())


@app.errorhandler(500)
def api_internal_error(_):
    # Flask otherwise produces an HTML error page that the frontend cannot parse.
    if request.path.startswith('/api/'):
        return jsonify(error='MyVectors internal server error (HTTP 500). '
                       'Check: docker compose logs --tail=100 myvectors'), 500
    return 'Internal server error', 500


@app.errorhandler(413)
def file_too_large(_):
    return jsonify(error='File exceeds 16 MB'), 413


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=42002, debug=False)
