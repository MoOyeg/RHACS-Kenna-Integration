from fastapi.testclient import TestClient
from .main import app
import json

client = TestClient(app)

def simple_parse_test():
    f = open('./json_examples/acs_alert_example.json')
    jsondata = json.load(f)
    f.close()
    
    response = client.post(
        "/recieve_acs_vuln_alert",
        json=jsondata,
    )
    assert response.status_code == 200   