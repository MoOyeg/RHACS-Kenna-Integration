from fastapi.testclient import TestClient
from .main import app
import json
import os

client = TestClient(app)
kde_output="kde_output_json"
acs_output="acs_example_json"
parent_dir=os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
full_kde_output=os.path.join(parent_dir,kde_output)
full_acs_output=os.path.join(parent_dir,acs_output)

def test_simple_parsing():
    f = open('{}/acs_alert_example.json'.format(full_acs_output),"r")
    jsondata = json.load(f)
    f.close()
    
    response = client.post(
        "/recieve_acs_vuln_alert",
        json=jsondata,
    )
    assert response.status_code == 200


def test_bulk_parsing():
    total_parsed_count=0
    total_parsed_pass_count=0
    total_failed_pass_count=0
       
    for filename in os.listdir(full_acs_output):
      jsondata=None
      filepath = os.path.join(full_acs_output, filename)
      # checking if it is a file
      if os.path.isfile(filepath):
        f = open(filepath,"r")
        try:
            jsondata = json.load(f)
        except ValueError:  # includes simplejson.decoder.JSONDecodeError
          print('Decoding JSON has failed for file{}'.format(filepath))
          f.close()
          continue       
        f.close()
        total_parsed_count += 1
      
      if jsondata is not None:
        response = client.post("/recieve_acs_vuln_alert",json=jsondata,)
        if response.status_code == 200:
            total_parsed_pass_count += 1
        else:
            total_failed_pass_count += 1
      
    assert total_failed_pass_count == 0
    assert total_parsed_pass_count == total_parsed_count