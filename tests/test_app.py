import io
import csv
import json
import pytest
from openpyxl import Workbook
import app as m

@pytest.fixture
def client(tmp_path):
    m.app.config['TESTING'] = True
    m.app.config['DB_PATH'] = str(tmp_path / 'data.sqlite3')
    with m.app.test_client() as c:
        yield c


def test_dns_nat_and_manual(client):
    wb = Workbook()
    s = wb.active
    s.append(['RR name','Type','TTL','Value'])
    s.append(['app.example.ch','A',300,'203.0.113.10'])
    s.append(['alias.example.ch','CNAME',120,'app.example.ch.'])
    s.append(['text.example.ch','TXT',300,'ignore'])
    buf = io.BytesIO(); wb.save(buf); buf.seek(0)
    r = client.post('/api/import/dns', data={'file':(buf,'domain-list.xlsx')})
    assert r.json['imported'] == 2
    assert client.post('/api/import/http2').status_code == 400
    nat = ('Name,Source_IP_Address_Start,Target_IP_Address_Start,Protocol,Source_Port_Start,Target_Port_Start\n'
           'rule1,203.0.113.10,10.0.0.10,tcp,443,8443\n')
    r = client.post('/api/import/nat',data={'file':(io.BytesIO(nat.encode()),'nat.csv')})
    assert r.json['imported'] == 1
    payload={'from_kind':'ip','from_key':'10.0.0.10','to_kind':'device','to_key':'proxy-01','relation':'belongs_to','confidence':'verified','note':'confirmed'}
    assert client.post('/api/connections',json=payload).status_code==200
    st = client.get('/api/state').json
    assert len(st['nodes']) == 5
    assert len(st['edges']) == 4
    assert all('http2_enabled' not in n['details'] for n in st['nodes'])
    # Import again; unique edges remain unique.
    r = client.post('/api/import/nat',data={'file':(io.BytesIO(nat.encode()),'nat.csv')})
    assert r.status_code == 200
    assert len(client.get('/api/state').json['edges']) == 4


def test_nat_ranges_and_invalid_input(client):
    with m.connect() as db:
        ct, skip=m.import_nat(db,[{'Source_IP_Address_Start':'192.0.2.10','Source_IP_Address_End':'192.0.2.12', 'Target_IP_Address_Start':'10.0.0.1','Name':'many-to-one'},
            {'Source_IP_Address_Start':'invalid','Target_IP_Address_Start':'10.0.0.1'}])
    assert (ct,skip)==(3,1)
    assert len(client.get('/api/state').json['edges'])==3
    assert client.post('/api/connections',json={'from_kind':'ip','from_key':'nonsense','to_kind':'device','to_key':'a','relation':'routes_to','confidence':'verified'}).status_code==400


def test_device42_import_helpers(client,monkeypatch):
    monkeypatch.setattr(m,'D42_URL','https://d42.example')
    with m.connect() as db:
        count=m.import_devices(db,[{'device_id':17,'name':'backend-01','os':'Linux','ip_addresses':[{'ip':'10.1.1.5'}]}])
    assert count == 1
    st=client.get('/api/state').json
    assert st['nodes'][0]['d42_url'].endswith('/admin/rackraj/device/17/')
    assert len(st['edges']) == 1
    assert m.extract_rows({'ipnats':[{'name':'A'}]},('ipnats',))==[{'name':'A'}]
    assert client.post('/api/d42/nat',json={}).status_code==400


def test_device42_settings_local_and_links_refresh(client, monkeypatch):
    monkeypatch.setattr(m, 'D42_URL', '')
    assert client.get('/api/settings').json == {'device42_url': '', 'device42_ip_path': m.DEFAULT_D42_IP_PATH}
    for invalid in ('http://d42.example', 'https://user:secret@d42.example',
                    'https://d42.example/admin', 'https://d42.example/?key=a',
                    'https://d42.example:bad', 'https://d42.example\n.evil.com'):
        assert client.put('/api/settings', json={'device42_url': invalid}).status_code == 400
    assert client.put('/api/settings', json={'device42_url': 'https://d42-one.example/'}).status_code == 200
    with m.connect() as db:
        assert m.import_devices(db, [{'device_id': 17, 'name': 'proxy',
            'ip_addresses': [{'ip': '10.1.1.5'}]}]) == 1
    device = next(n for n in client.get('/api/state').json['nodes'] if n['kind'] == 'device')
    assert device['d42_url'] == 'https://d42-one.example/admin/rackraj/device/17/'
    assert client.put('/api/settings', json={'device42_url': 'https://d42-two.example'}).status_code == 200
    device = next(n for n in client.get('/api/state').json['nodes'] if n['kind'] == 'device')
    assert device['d42_url'].startswith('https://d42-two.example/')
    calls = []
    class Resp:
        def raise_for_status(self):
            pass
        def json(self):
            return {'devices': []}
    def fake_get(url, **kw):
        calls.append((url, kw))
        return Resp()
    monkeypatch.setattr(m.requests, 'get', fake_get)
    m.d42_get('/api/1.0/devices/all/', ('analyst', 'password'), {'limit': 1})
    assert calls[0][0] == 'https://d42-two.example/api/1.0/devices/all/'
    assert calls[0][1]['auth'] == ('analyst', 'password')
    assert 'password' not in str(client.get('/api/settings').json)
    assert client.put('/api/settings', json={'device42_url': ''}).status_code == 200


def test_delete_objects_single_bulk_and_atomic(client):
    with m.connect() as db:
        a = m.node(db, 'domain', 'first.example')
        b = m.node(db, 'ip', '203.0.113.12')
        c = m.node(db, 'device', 'proxy')
        m.edge(db, a, b, 'resolves_to', 'dns')
        m.edge(db, b, c, 'belongs_to', 'manual')
    assert client.post('/api/nodes/delete', json={'ids': [True]}).status_code == 400
    assert client.post('/api/nodes/delete', json={'ids': []}).status_code == 400
    assert client.post('/api/nodes/delete', json={'ids': [a, 999999]}).status_code == 404
    assert len(client.get('/api/state').json['nodes']) == 3
    response = client.post('/api/nodes/delete', json={'ids': [b, b]})
    assert response.status_code == 200
    assert response.json == {'deleted': 1, 'connections_deleted': 2}
    state = client.get('/api/state').json
    assert len(state['nodes']) == 2
    assert state['edges'] == []
    response = client.post('/api/nodes/delete', json={'ids': [a, c]})
    assert response.json['deleted'] == 2
    assert client.get('/api/state').json['nodes'] == []


def test_nat_import_diagnostics(client):
    diagnostics = {}
    with m.connect() as db:
        count, skipped = m.import_nat(db, [
            {'id': 1, 'src_ip': '192.0.2.1', 'dst_ip': '10.0.0.1'},
            {'Source_IP_Address_Start': '203.0.113.2', 'Target_IP_Address_Start': '10.0.0.2'}
        ], diagnostics=diagnostics)
    assert (count, skipped) == (1, 1)
    assert diagnostics['skip_reasons'] == {'missing_source_or_target_ip': 1}
    assert 'src_ip' in diagnostics['api_field_names']
    assert '192.0.2.1' not in str(diagnostics)


def test_device42_real_nat_api_field_names(client):
    diagnostics = {}
    rows = [
        {'id': 7, 'name': 'web-443', 'ip_address_from': '203.0.113.10',
         'ip_address_to': '10.0.0.10', 'source_port_start': 443,
         'target_port_start': 8443, '__from_api': True},
        {'id': 8, 'name': 'range', 'ip_address_from': '198.51.100.20',
         'ip_address_from_end': '198.51.100.21',
         'ip_address_to': '10.0.0.20', 'ip_address_to_end': '10.0.0.21',
         '__from_api': True}
    ]
    with m.connect() as db:
        count, skipped = m.import_nat(db, rows, diagnostics=diagnostics)
    assert (count, skipped) == (3, 0)
    assert diagnostics['skip_reasons'] == {}
    st = client.get('/api/state').json
    assert len(st['edges']) == 3
    assert all(e['origin'] == 'd42_nat' for e in st['edges'])
    assert any(e['details']['target_port'] == '8443' for e in st['edges'])


def test_ip_links_match_existing_nodes_only_and_avoid_ambiguous_vrfs(client):
    assert client.put('/api/settings', json={'device42_url': 'https://d42.example'}).status_code == 200
    with m.connect() as db:
        m.node(db, 'ip', '203.0.113.10')
        m.node(db, 'ip', '10.0.0.10')
        m.node(db, 'ip', '10.0.0.11')
        m.node(db, 'domain', 'web.example')
    rows = [
        {'ipaddress': '203.0.113.10', 'id': 101},
        {'ip_address': '10.0.0.10', 'ip_address_id': 202},
        {'ip': '10.0.0.10', 'id': '203', 'vrf_group': 'other'},
        {'ipaddress': '192.0.2.100', 'id': 555}
    ]
    with m.connect() as db:
        result = m.import_ip_links(db, rows)
    assert result['linked'] == 1
    assert result['ambiguous'] == 1
    assert result['not_found'] == 1
    state = client.get('/api/state').json
    by_key = {x['key']: x for x in state['nodes']}
    assert len(state['nodes']) == 4
    assert by_key['203.0.113.10']['d42_url'] == 'https://d42.example/admin/rackraj/ipaddress/101/'
    assert by_key['10.0.0.10']['d42_url'] == ''
    assert by_key['10.0.0.10']['details']['d42_ip_status'] == 'ambiguous'
    assert by_key['10.0.0.11']['d42_url'] == ''
    assert client.put('/api/settings', json={'device42_url': 'https://other.example',
        'device42_ip_path': '/custom/ip/{id}/'}).status_code == 200
    state = client.get('/api/state').json
    new_url = next(x['d42_url'] for x in state['nodes'] if x['key']=='203.0.113.10')
    assert new_url == 'https://other.example/custom/ip/101/'
    assert client.put('/api/settings', json={'device42_url': 'https://other.example',
        'device42_ip_path': '//bad/{id}/'}).status_code == 400
    assert client.put('/api/settings', json={'device42_url': 'https://other.example',
        'device42_ip_path': '/bad/link'}).status_code == 400
    with m.connect() as db:
        result = m.import_ip_links(db, [{'ipaddress': '203.0.113.10', 'id': 101}])
    state = client.get('/api/state').json
    assert next(x for x in state['nodes'] if x['key']=='10.0.0.10')['d42_url'] == ''


def test_ip_links_schema_validation_and_api_endpoint(client, monkeypatch):
    with m.connect() as db:
        m.node(db, 'ip', '198.51.100.14')
    with m.connect() as db:
        with pytest.raises(ValueError, match='schema not recognized'):
            m.import_ip_links(db, [{'unexpected': 'value'}])
    monkeypatch.setattr(m, 'D42_URL', 'https://d42.example')
    calls = []
    def fake_pages(path, names, credentials):
        calls.append((path, names, credentials))
        return [{'ipaddress': '198.51.100.14', 'id': 88}]
    monkeypatch.setattr(m, 'd42_pages', fake_pages)
    result = client.post('/api/d42/ip_links', json={'username': 'demo', 'password': 'transient'})
    assert result.status_code == 200
    assert result.json['linked'] == 1
    assert calls[0][0] == '/api/1.0/ips/'
    assert calls[0][2] == ('demo', 'transient')
    assert 'transient' not in str(client.get('/api/state').json)
