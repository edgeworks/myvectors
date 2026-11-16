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
        status_code = 200
        headers = {'Content-Type': 'application/json'}
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


def test_targeted_nat_ip_lookup_and_links(client, monkeypatch):
    assert client.put('/api/settings', json={'device42_url': 'https://d42.example'}).status_code == 200
    with m.connect() as db:
        a=m.node(db, 'ip', '203.0.113.10')
        b=m.node(db, 'ip', '10.0.0.10')
        m.edge(db,a,b,'nat_to','d42_nat')
        m.node(db, 'ip', '10.0.0.11',details={'d42_ip_id':'unrelated'})
    calls=[]
    def fake_lookup(credentials, ips):
        calls.append(ips)
        return [{'ip_address':'203.0.113.10','ipaddress_pk':101},
                {'ip_address':'10.0.0.10','ipaddress_pk':202},
                {'ip_address':'10.0.0.10','ipaddress_pk':203}]
    monkeypatch.setattr(m,'d42_nat_ip_query',fake_lookup)
    r=client.post('/api/d42/ip_links/page',json={'username':'u','password':'pw'})
    assert r.status_code==200
    assert r.json['done'] is True
    assert r.json['linked']==1 and r.json['ambiguous']==1
    assert set(calls[0])=={'203.0.113.10','10.0.0.10'}
    data={n['key']:n for n in client.get('/api/state').json['nodes']}
    assert data['203.0.113.10']['d42_url']=='https://d42.example/admin/rackraj/ipaddress/101/'
    assert data['10.0.0.10']['d42_url']==''
    assert data['10.0.0.10']['details']['d42_ip_status']=='ambiguous'
    assert data['10.0.0.11']['details']['d42_ip_id']=='unrelated'
    assert client.put('/api/settings',json={'device42_url':'https://new.example',
        'device42_ip_path':'/custom/{id}/'}).status_code==200
    data={n['key']:n for n in client.get('/api/state').json['nodes']}
    assert data['203.0.113.10']['d42_url']=='https://new.example/custom/101/'


def test_targeted_nat_ip_lookup_requires_nat_edges(client):
    with m.connect() as db:
        m.node(db,'ip','192.0.2.10')
    r=client.post('/api/d42/ip_links/page',json={'username':'u','password':'p'})
    assert r.status_code==502
    assert 'Import NAT data first' in r.json['error']


def test_device42_response_diagnostics(client, monkeypatch):
    monkeypatch.setattr(m, 'D42_URL', 'https://d42.example')
    assert m.extract_rows({'Devices': {'devices': [{'device_id': 77}]}},
                          ('devices',)) == [{'device_id': 77}]
    assert m.extract_rows({'Devices': [{'device_id': 77}]},
                          ('devices',)) == [{'device_id': 77}]
    class Response:
        def __init__(self, status, content_type, body):
            self.status_code = status
            self.headers = {'Content-Type': content_type}
            self.body = body
        def json(self):
            if isinstance(self.body, Exception):
                raise self.body
            return self.body

    results = [
        (Response(302, 'text/html', ValueError('redirect login page')), 'HTTP 302 redirect'),
        (Response(200, 'text/html', ValueError('html login page')), 'instead of JSON'),
        (Response(404, 'text/html', ValueError('not found page')), 'HTTP 404'),
    ]
    for response, error in results:
        monkeypatch.setattr(m.requests, 'get', lambda *args, **kwargs: response)
        with pytest.raises(ValueError, match=error):
            m.d42_get('/api/1.0/ips/', ('user', 'secret'), {'limit': 1000})

    monkeypatch.setattr(m.requests, 'get', lambda *args, **kwargs:
                        Response(200, 'application/json', {'ips': [{'id': 1}]}))
    assert m.d42_get('/api/1.0/ips/', ('user', 'secret'), {}) == {'ips': [{'id': 1}]}



def test_ip_page_import_stages_until_complete(client, monkeypatch):
    assert client.put('/api/settings',json={'device42_url':'https://d42.example'}).status_code==200
    monkeypatch.setitem(m.D42_PAGE_SIZES,'ip_links',2)
    with m.connect() as db:
        ids=[m.node(db,'ip',addr) for addr in ('10.1.1.1','10.1.1.2','10.1.1.3')]
        for i in (1,2):
            m.edge(db,ids[0],ids[i],'nat_to','d42_nat')
        m.node(db,'ip','192.0.2.2',details={'d42_ip_id':'other'})
        m.node(db,'ip','10.1.1.1',details={'d42_ip_id':'old'})
    calls=[]
    def fake_lookup(credentials,ips):
        calls.append(ips)
        out=[{'ip_address':ip,'ipaddress_pk':int(ip.rsplit('.',1)[-1])} for ip in ips]
        if '10.1.1.2' in ips:
            out.append({'ip_address':'10.1.1.2','ipaddress_pk':999})
        return out
    monkeypatch.setattr(m,'d42_nat_ip_query',fake_lookup)
    args={'username':'user','password':'password'}
    first=client.post('/api/d42/ip_links/page',json={**args,'offset':0})
    assert first.status_code==200
    assert first.json['received']==2
    assert first.json['total_count']==3
    assert first.json['done'] is False
    before={n['key']:n for n in client.get('/api/state').json['nodes']}
    assert before['10.1.1.1']['details']['d42_ip_id']=='old'
    bad=client.post('/api/d42/ip_links/page',json={**args,'offset':2,'run_id':'invalid'})
    assert bad.status_code==502
    second=client.post('/api/d42/ip_links/page',
                       json={**args,'offset':2,'run_id':first.json['run_id']})
    assert second.status_code==200
    assert second.json['done'] is True
    assert second.json['linked']==2
    assert second.json['ambiguous']==1
    state={n['key']:n for n in client.get('/api/state').json['nodes']}
    assert state['10.1.1.1']['details']['d42_ip_id']=='1'
    assert state['10.1.1.2']['details']['d42_ip_status']=='ambiguous'
    assert state['192.0.2.2']['details']['d42_ip_id']=='other'
    assert len(calls)==2
    with m.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM d42_ip_runs').fetchone()[0]==0
        assert db.execute('SELECT COUNT(*) FROM d42_ip_targets').fetchone()[0]==0
        assert db.execute('SELECT COUNT(*) FROM d42_ip_candidates').fetchone()[0]==0


def test_targeted_lookup_rejects_extra_records_and_preserves_data(client, monkeypatch):
    with m.connect() as db:
        a=m.node(db,'ip','203.0.113.3',details={'d42_ip_id':'old'})
        b=m.node(db,'ip','10.10.10.1')
        m.edge(db,a,b,'nat_to','nat_csv')
    monkeypatch.setattr(m,'d42_nat_ip_query',
                        lambda creds, ips: [{'ip_address':'8.8.8.8','ipaddress_pk':55}])
    r=client.post('/api/d42/ip_links/page',json={'username':'a','password':'b'})
    assert r.status_code==502
    assert 'outside the requested' in r.json['error']
    state={n['key']:n for n in client.get('/api/state').json['nodes']}
    assert state['203.0.113.3']['details']['d42_ip_id']=='old'
    monkeypatch.setattr(m,'d42_nat_ip_query',lambda creds,ips: [])
    r=client.post('/api/d42/ip_links/page',json={'username':'a','password':'b'})
    assert r.status_code==200
    assert r.json['no_matches_preserved'] is True
    state={n['key']:n for n in client.get('/api/state').json['nodes']}
    assert state['203.0.113.3']['details']['d42_ip_id']=='old'


def test_doql_post_sends_only_known_ip_addresses(client,monkeypatch):
    monkeypatch.setattr(m,'D42_URL','https://d42.example')
    sent=[]
    class Response:
        status_code=200
        def json(self):
            return {'data':[{'ip_address':'10.0.0.1','ipaddress_pk':1}]}
    def fake_post(url,**kwargs):
        sent.append((url,kwargs))
        return Response()
    monkeypatch.setattr(m.requests,'post',fake_post)
    data=m.d42_nat_ip_query(('analyst','secret'),['10.0.0.1'])
    assert data==[{'ip_address':'10.0.0.1','ipaddress_pk':1}]
    assert sent[0][0]=='https://d42.example/services/data/v1.0/query/'
    assert 'WHERE ip_address IN (\'10.0.0.1\')' in sent[0][1]['data']['query']
    assert sent[0][1]['data']['output_type']=='json'
    assert sent[0][1]['auth']==('analyst','secret')


def test_devices_import_one_page_per_request(client, monkeypatch):
    monkeypatch.setitem(m.D42_PAGE_SIZES, 'devices', 2)
    def fake_get(path, credentials, params):
        records = [
            {'name': 'server-a', 'device_id': 1, 'ip_addresses': [{'ip': '10.1.2.1'}]},
            {'name': 'server-b', 'device_id': 2, 'ip_addresses': [{'ip': '10.1.2.2'}]},
            {'name': 'server-c', 'device_id': 3, 'ip_addresses': [{'ip': '10.1.2.3'}]},
        ]
        return {'devices': records[params['offset']:params['offset']+params['limit']],
                'total_count': len(records)}
    monkeypatch.setattr(m, 'd42_get', fake_get)
    creds = {'username': 'user', 'password': 'secret'}
    first = client.post('/api/d42/devices/page', json=creds)
    assert first.status_code == 200
    assert first.json['received'] == 2
    assert first.json['done'] is False
    second = client.post('/api/d42/devices/page', json={**creds, 'offset': 2})
    assert second.status_code == 200
    assert second.json['done'] is True
    assert second.json['imported'] == 1
    state = client.get('/api/state').json
    assert len([n for n in state['nodes'] if n['kind'] == 'device']) == 3
    assert len(state['edges']) == 3


def test_page_import_reports_device42_timeout(client, monkeypatch):
    def failed_get(*args, **kwargs):
        raise m.requests.Timeout('Device42 timed out')
    monkeypatch.setattr(m, 'd42_nat_ip_query', failed_get)
    with m.connect() as db:
        a=m.node(db,'ip','203.0.113.1')
        b=m.node(db,'ip','10.0.0.1')
        m.edge(db,a,b,'nat_to','d42_nat')
    r = client.post('/api/d42/ip_links/page',
                    json={'username': 'u', 'password': 'p'})
    assert r.status_code == 504
    assert 'did not respond' in r.json['error']
    assert 'Device42 timed out' not in r.json['error']
