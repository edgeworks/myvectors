"""MyVectors: on-demand exposure-path inventory (no automatic scanning)."""
import csv
import io
import ipaddress
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

import requests
from flask import Flask, jsonify, request, send_from_directory
from openpyxl import load_workbook

BASE = Path(__file__).resolve().parent
DB_PATH = os.environ.get('MYVECTORS_DB', str(BASE / 'data' / 'myvectors.sqlite3'))
D42_URL = os.environ.get('DEVICE42_URL', '').rstrip('/')
D42_VERIFY_TLS = os.environ.get('D42_VERIFY_TLS', 'true').lower() == 'true'
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
      CREATE INDEX IF NOT EXISTS edges_src ON edges(src);
      CREATE INDEX IF NOT EXISTS edges_dst ON edges(dst);
    ''')
    return db


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


def import_http2(db, rows):
    count = 0
    for r in rows:
        domain = val(r, 'domain')
        enabled = val(r, 'http2_enabled').upper()
        if not domain or enabled not in ('YES', 'NO'):
            continue
        node(db, 'domain', domain, details={'http2_enabled': enabled,
             'http_version': val(r, 'http_version'), 'http_status': val(r, 'http_status'),
             'http2_checked_at': now()})
        count += 1
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


def import_nat(db, rows):
    count, skipped = 0, 0
    for r in rows:
        src = val(r, 'Source_IP_Address_Start', 'source_ip_start')
        dst = val(r, 'Target_IP_Address_Start', 'target_ip_start')
        if not src or not dst:
            skipped += 1
            continue
        try:
            sources = ip_range(src, val(r, 'Source_IP_Address_End'))
            targets = ip_range(dst, val(r, 'Target_IP_Address_End'))
        except ValueError:
            skipped += 1
            continue
        if len(targets) not in (1, len(sources)):
            skipped += 1
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
    return count, skipped


def extract_rows(payload, names):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        normalized = canon(payload)
        for name in names:
            found = normalized.get(re.sub(r'[^a-z0-9]', '', name.lower()))
            if isinstance(found, list):
                return found
        for k in ('results', 'data', 'items'):
            if isinstance(payload.get(k), list):
                return payload[k]
    raise ValueError('Unrecognized Device42 response shape; no changes were imported')


def d42_get(path, credentials, params):
    if not D42_URL or urlparse(D42_URL).scheme != 'https':
        raise ValueError('Set DEVICE42_URL to the HTTPS URL of your appliance')
    response = requests.get(D42_URL + path, params=params, auth=credentials,
                            verify=D42_VERIFY_TLS, timeout=25,
                            headers={'Accept': 'application/json'})
    response.raise_for_status()
    return response.json()


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
        link = (D42_URL + '/admin/rackraj/device/' + quote(device_id) + '/') if device_id.isdigit() else ''
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
    for x in nodes + edges:
        x['details'] = json.loads(x['details'])
    return {'nodes': nodes, 'edges': edges}


@app.get('/')
def home():
    return send_from_directory('static', 'index.html')


@app.get('/api/state')
def state():
    return jsonify(response_state())


@app.post('/api/import/<kind>')
def file_import(kind):
    if kind not in ('dns', 'http2', 'nat'):
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
        if kind == 'http2':
            with connect() as db:
                count = import_http2(db, rows)
            return jsonify(imported=count)
        with connect() as db:
            count, skipped = import_nat(db, rows)
        return jsonify(imported=count, skipped=skipped)
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


@app.post('/api/d42/<kind>')
def device42_import(kind):
    if kind not in ('nat', 'devices'):
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
            with connect() as db:
                count, skipped = import_nat(db, rows)
            return jsonify(imported=count, skipped=skipped)
        rows = d42_pages('/api/1.0/devices/all/', ('devices',), credentials)
        with connect() as db:
            count = import_devices(db, rows)
        return jsonify(imported=count, devices_received=len(rows))
    except (requests.RequestException, ValueError) as exc:
        # Avoid returning upstream response bodies (may contain sensitive data).
        return jsonify(error=f'Device42 import failed: {type(exc).__name__}: {str(exc)[:180]}'), 502


@app.get('/api/export')
def export():
    return jsonify(response_state())


@app.errorhandler(413)
def file_too_large(_):
    return jsonify(error='File exceeds 16 MB'), 413


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=42002, debug=False)
