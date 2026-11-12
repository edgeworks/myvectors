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
    assert client.get('/api/settings').json == {'device42_url': ''}
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
