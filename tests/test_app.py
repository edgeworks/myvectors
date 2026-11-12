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


def test_dns_http2_nat_and_manual(client):
    wb = Workbook()
    s = wb.active
    s.append(['RR name','Type','TTL','Value'])
    s.append(['app.example.ch','A',300,'203.0.113.10'])
    s.append(['alias.example.ch','CNAME',120,'app.example.ch.'])
    s.append(['text.example.ch','TXT',300,'ignore'])
    buf = io.BytesIO(); wb.save(buf); buf.seek(0)
    r = client.post('/api/import/dns', data={'file':(buf,'domain-list.xlsx')})
    assert r.json['imported'] == 2
    r = client.post('/api/import/http2',data={'file':(io.BytesIO(b'domain,http_version,http_status,http2_enabled\napp.example.ch,2,200,YES\n'), 'http2.csv')})
    assert r.json['imported'] == 1
    nat = ('Name,Source_IP_Address_Start,Target_IP_Address_Start,Protocol,Source_Port_Start,Target_Port_Start\n'
           'rule1,203.0.113.10,10.0.0.10,tcp,443,8443\n')
    r = client.post('/api/import/nat',data={'file':(io.BytesIO(nat.encode()),'nat.csv')})
    assert r.json['imported'] == 1
    payload={'from_kind':'ip','from_key':'10.0.0.10','to_kind':'device','to_key':'proxy-01','relation':'belongs_to','confidence':'verified','note':'confirmed'}
    assert client.post('/api/connections',json=payload).status_code==200
    st = client.get('/api/state').json
    assert len(st['nodes']) == 5
    assert len(st['edges']) == 4
    assert next(n for n in st['nodes'] if n['key']=='app.example.ch')['details']['http2_enabled']=='YES'
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
