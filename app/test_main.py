from fastapi.testclient import TestClient
from .main import app,acs_alert_message_parser
from logging import getLogger, config
import asyncio
import json
import os

#Init
client = TestClient(app)
kde_output="kde_output_json"
acs_output="acs_example_json"
#Logging
log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logging.conf')
config.fileConfig(log_file_path, disable_existing_loggers=False)
logger = getLogger("logger_root")
parent_dir=os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
full_kde_output=os.path.join(parent_dir,kde_output)
full_acs_output=os.path.join(parent_dir,acs_output)

def is_jsonseriazable(x):
    try:
        json.dumps(x)
        return True
    except (TypeError, OverflowError):
        return False

def test_receive():
    """ Testing that when we send a correct json we recieve a 200"""
    f = open('{}/acs_alert_example.json'.format(full_acs_output),"r")
    jsondata = json.load(f)
    f.close()
    
    response = client.post(
        "/recieve_acs_vuln_alert",
        json=jsondata,
    )
    assert response.status_code == 200

def test_receive_valid_json():
    """ Testing that when we send a correct jsonand ask for a result we recieve a valid json response"""
    f = open('{}/acs_alert_example.json'.format(full_acs_output),"r")
    jsondata = json.load(f)
    f.close()
    
    response = client.post(
        "/recieve_acs_vuln_alert/?return_flag=all",
        json=jsondata,
    )
    
    assert response.status_code == 200
    assert is_jsonseriazable(response.json())

def test_bulk_receive():
    total_parsed_count=0
    total_parsed_pass_count=0
    total_parsed_fail_count=0
       
    for filename in os.listdir(full_acs_output):
      jsondata=None
      filepath = os.path.join(full_acs_output, filename)
      # checking if it is a file
      if os.path.isfile(filepath):
        f = open(filepath,"r")
        try:
            jsondata = json.load(f)
        except ValueError:  # includes simplejson.decoder.JSONDecodeError
          logger.error('Decoding JSON has failed for file{}'.format(filepath))
          f.close()
          continue       
        f.close()
        total_parsed_count += 1
      
      if jsondata is not None:
        response = client.post("/recieve_acs_vuln_alert",json=jsondata,)
        if response.status_code == 200:
            total_parsed_pass_count += 1
        else:
            total_parsed_fail_count += 1
      
    assert total_parsed_fail_count == 0
    assert total_parsed_pass_count == total_parsed_count
    
def test_bulk_recieve_valid_json():
    total_serializable_count=0
    total_serializable_pass_count=0
    total_serializable_fail_count=0
       
    for filename in os.listdir(full_acs_output):
      jsondata=None
      filepath = os.path.join(full_acs_output, filename)
      # checking if it is a file
      if os.path.isfile(filepath):
        f = open(filepath,"r")
        try:
            jsondata = json.load(f)
        except ValueError:  # includes simplejson.decoder.JSONDecodeError
          logger.error('Decoding JSON has failed for file{}'.format(filepath))
          f.close()
          continue       
        f.close()
        total_serializable_count += 1
      
      if jsondata is not None:
        response = client.post("/recieve_acs_vuln_alert/?return_flag=all",json=jsondata,)
        if is_jsonseriazable(response.json()):
            total_serializable_pass_count += 1
        else:
            total_serializable_fail_count += 1
      
    assert total_serializable_fail_count == 0
    assert total_serializable_pass_count == total_serializable_count
    
def test_bulk_acs_alert_message_parser():
    """ Testing that when we send a correct json our parser can correctly parse messages"""
    total_regexable_count=0
    total_regexable_pass_count=0
    total_regexable_fail_count=0
       
    for filename in os.listdir(full_acs_output):
      jsondata=None
      filepath = os.path.join(full_acs_output, filename)
      # checking if it is a file
      if os.path.isfile(filepath):
        f = open(filepath,"r")
        try:
            jsondata = json.load(f)
        except ValueError:  # includes simplejson.decoder.JSONDecodeError
          logger.error('Decoding JSON has failed for file{}'.format(filepath))
          f.close()
          continue       
        f.close()

      if jsondata is not None:            
        response = client.post("/recieve_acs_vuln_alert/?return_flag=message",json=jsondata,)
        violation=json.loads(response.json())
        for message in violation["violations"]:
          try:
            temp_message = message["message"]
          except:
            total_regexable_fail_count += 1
            logger.error("Could not Parse Message:\n")
            logger.error("{}".format(temp_message))            
          if message is not None:
            total_regexable_count+=1
            output = asyncio.run(acs_alert_message_parser(temp_message))
            if output is None:
              total_regexable_fail_count += 1
              logger.error("Could not Parse Message:\n")
              logger.error("{}".format(temp_message))
              continue
            try:            
                cvss_name=output["cvss_name"]
                cvss_score=output["cvss_score"]
                vuln_severity=output["vuln_severity"]
                vuln_affected_image_version=output["vuln_affected_image_version"]
                vuln_affected_container_name=output["vuln_affected_container_name"]
                total_regexable_pass_count+=1
            except KeyError:
                logger.error("Could not Parse Message:\n")
                logger.error("{}".format(temp_message))
                total_regexable_fail_count += 1                
    
    assert total_regexable_fail_count == 0
    assert total_regexable_count == total_regexable_pass_count        
                           
