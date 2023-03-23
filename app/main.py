# pylint: disable=invalid-name
'''
Version 1: Prototype
'''

from asyncio import get_event_loop
from concurrent.futures import ThreadPoolExecutor
from logging import getLogger, config
from os import getenv
from typing import Union,TypeVar, Generic  # pylint: disable=import-error
from pydantic import BaseModel,Extra,create_model  # pylint: disable=import-error
from fastapi import FastAPI,Request,Body,Response # pylint: disable=import-error
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pathlib import Path, _ignore_error as pathlib_ignore_error
from fastapi.encoders import jsonable_encoder
from os import path,pardir
from aiofiles import os as async_os,open as async_open
import json ,re


class AppModel(BaseModel):
    
  def dict(self, *args, **kwargs):
    if kwargs and kwargs.get("exclude_none") is not None:
      kwargs["exclude_none"] = True
      return BaseModel.dict(self, *args, **kwargs)

class KDEVulnDef(BaseModel):
    scanner_type: str | None
    cve_identifiers: str | None
    wasc_identifiers: str | None
    cwe_identifiers: str | None
    name: str | None
    description: str | None
    solution: str = ""

class KDEFinding(BaseModel):
    scanner_identifier: str
    scanner_type: str
    created_at: str | None
    due_date: str | None
    last_seen_at: str
    severity: int | None
    triage_state: str | None	
    additional_fields: list | None
    vuln_def_name: str

class KDEvuln(BaseModel):
    scanner_identifier: str
    scanner_type: str 
    scanner_score: int
    override_score: int | None
    created_at: str | None
    last_seen_at: str | None
    last_fixed_on: str | None
    status: str | None
    port: int | None
    vuln_def_name: str
    
class KDEAsset(BaseModel,extra=Extra.allow):
    file: str | None
    ip_address: str | None
    mac_address: str | None
    hostname: str | None
    ec2: str | None
    netbios: str | None
    url: str | None
    fqdn: str | None
    image_id: str | None
    container_id: str | None
    external_id: str | None	
    database: str | None
    application: str | None
    tags: list[str] | None
    owner: str | None
    os: str | None
    os_version: str | None
    priority: str | None
    asset_type: str | None
    vulns: list[KDEvuln] 
    findings: list[KDEFinding] | None
      
class KDEJsonv2(AppModel):
    skip_autoclose: bool = False
    version: int = 2
    assets: list[KDEAsset]
    reset_tags: bool = False
    vuln_defs: list[KDEVulnDef] | None
 
class ACSViolations(BaseModel):
    message: str
    
class ACSImageDetails(BaseModel):
    registry: str
    remote: str
    fullName: str
    
class ACSImage(BaseModel):
    id: str | None = None
    name: ACSImageDetails

class ACSContainer(BaseModel):
    name: str
    image: ACSImage

class ACSDeployment(BaseModel):
    '''Affected RHACS Deployment as recieved from Vulnerability Data'''
    id: str
    name: str
    type: str
    namespace: str
    namespaceId: str
    labels: dict | None = None
    clusterId: str
    clusterName: str
    containers: list[ACSContainer]
    annotations: dict | None = None

class ACSPolicy(BaseModel):
    '''Policy Information for Policy generating this Violation'''
    id: str
    name: str
    categories: list
    lifecycleStages: list
    severity: str
    notifiers: list
    lastUpdated: str
    SORTName: str
    SORTLifecycleStage: str
    policyVersion: str 
    policySections: list
    
class ACSAlert(BaseModel,extra=Extra.allow):  # pylint: disable=too-few-public-methods
    '''Class For Alert Information from RHACS'''
    id: str
    policy: ACSPolicy
    clusterId: str
    clusterName: str
    namespace: str
    namespaceId: str
    deployment: ACSDeployment
    violations: list[ACSViolations]
    time: str
    firstOccurred: str

#App Init

#Logging
log_file_path = path.join(path.dirname(path.abspath(__file__)), 'logging.conf')
config.fileConfig(log_file_path, disable_existing_loggers=False)
logger = getLogger("logger_root")

#Output Folder Directories
kde_output="kde_output_json"
acs_output="acs_example_json"
parent_dir=path.abspath(path.join(path.dirname(path.abspath(__file__)), pardir))
full_kde_output=path.join(parent_dir,kde_output)
full_acs_output=path.join(parent_dir,acs_output)

#Other Variables
scanner_type="rhacs_scanner"
count=0

#Declare App as a FastApi Object
app = FastAPI()

#Instance Hostname is global
instance_hostname = ""

def sync_write_file(fullfilepath,acsalert=None,kdeobject=None,content=None,mode="w+"):
    """ Method to synchonously write to Files"""
    
async def path_exists(path: Union[Path, str]) -> bool:
    try:
        await async_os.stat(str(path))
    except OSError as e:
        if not pathlib_ignore_error(e):
            raise
        return False
    except ValueError:
        # Non-encodable path
        return False
    return True    

async def async_write_file(fullfilepath,acsalert=None,kdeobject=None,content=None,mode="w+"):
    """ Method to Asynchonously write to Files"""
    if kdeobject is not None and acsalert is not None:
        tempfullfilepath='{}/{}.json'.format(fullfilepath,acsalert.deployment.id)
        count=1
        while await path_exists(tempfullfilepath):            
            tempfullfilepath='{}/{}_{}.json'.format(fullfilepath,acsalert.deployment.id,count)
            count += 1
        filehandle = await async_open(tempfullfilepath, mode='w+')
        await filehandle.write(json.dumps(jsonable_encoder(kdeobject),indent=2))
        filehandle.close
    
async def return_scanner_type() -> str:
    """Returns ACS Scanner Type, In future might implement logic to filter ACS Instances"""
    global scanner_type
    return scanner_type

async def acs_alert_message_parser(msg) -> dict:
    """Function to parse ACS Policy Violation Message to Get Vulnerability Information"""
    return_dict={}
    regex_pal1 = "(^\w+-[0-9\-\:]+)\s\(CVSS\s([0-9\.]+)\)\s\(severity\s(\w+)\)\sfound in component\s\'[\w\-\+\_\*\.]*\'\s\(([\w\s\-\.\_\:\+]*)\)\sin\scontainer\s\'([\w\-]+)\'"
    output=re.findall(regex_pal1, str(msg))
    if output is not None:
        try:
            return_dict.update({"cvss_name":output[0][0]})
            return_dict.update({"cvss_score":output[0][1]})
            return_dict.update({"vuln_severity":output[0][2]})
            return_dict.update({"vuln_affected_image_version":output[0][3]})
            return_dict.update({"vuln_affected_container_name":output[0][4]})
            return return_dict
        except:
            logger.error("Could not correctly parse msg -- {}".format(msg))            
    return None

#Write Output To KDE
async def write_out_kde(acsalert:ACSAlert):
    """ Write Received ACS Alert to KDE File"""
    
    #Create ACS Vulnerability in KDE
    
    #Vuln And Vuldef Storage
    temp_kde_vuln=[]
    temp_kde_vuln_def=[]
    temp_kde_finding=[]
    
    #Vuln and VulnDev List for Lookback to avoid duplicate
    temp_kde_vuln_name=[]
    temp_kde_vuln_def_name=[]
    for violation in acsalert.violations:
        output = await acs_alert_message_parser(violation.message)
        
        if output is None:
            logger.error("Could not correctly parse {}".format(acsalert.id))
            return None
        
        #With Data From ACS Message Parsing Update our Variables
        try:            
            cvss_name=output["cvss_name"]
            cvss_score=output["cvss_score"]
            vuln_severity=output["vuln_severity"]
            vuln_affected_image_version=output["vuln_affected_image_version"]
            vuln_affected_container_name=output["vuln_affected_container_name"]
        except KeyError:
            logger.error("Could not correctly parse ACS Alert -- {}".format(acsalert.id))
            logger.error("Cannot Output KDE for {}".format(acsalert.id))
            return None
            
        #In case CVSS Score is a float try
        try:
            cvss_score=int(cvss_score)
        except ValueError:
            try:
                cvss_score=float(cvss_score)
                cvss_score=int(cvss_score)
            except:
                logger.error("Could not convert CVSS Score into Int for KDE - {}".format(acsalert.id))
                return None
            
        #Add Vuln Definition into KDE,Check if already added
        if cvss_name not in temp_kde_vuln_def_name:
            new_vuln_def = KDEVulnDef(name=cvss_name
                                      ,scanner_type=await return_scanner_type()
                                      ,cve_identifiers = cvss_name
                                      ,description = vuln_severity)
            temp_kde_vuln_def.append(new_vuln_def)
            temp_kde_vuln_def_name.append(cvss_name)
        
        if cvss_name not in temp_kde_vuln_name:
            new_vuln = KDEvuln(scanner_identifier = acsalert.acs_instance_ip
                               ,scanner_type = await return_scanner_type()
                               ,scanner_score = cvss_score
                               ,last_seen_at = acsalert.firstOccurred
                               ,status = "open"
                               ,vuln_def_name = cvss_name)
            temp_kde_vuln.append(new_vuln)
            temp_kde_vuln_name.append(cvss_name)
            
            new_finding= KDEFinding(scanner_identifier = acsalert.acs_instance_ip
                               ,scanner_type = await return_scanner_type()
                               ,scanner_score = cvss_score
                               ,last_seen_at = acsalert.firstOccurred
                               ,vuln_def_name = cvss_name)
            temp_kde_finding.append(new_finding)
    
    #Create Deployment As KDE Assets
    new_kdeasset=KDEAsset(external_id=acsalert.deployment.id,vulns=temp_kde_vuln,findings=temp_kde_finding)


    #Pass Deployment Labels to Asset Tags
    if acsalert.deployment.labels is not None:
        if new_kdeasset.tags is None:
            new_kdeasset.tags = []
        for key in acsalert.deployment.labels:
            new_kdeasset.tags.append("{}:{}".format(key,acsalert.deployment.labels[key]))
    
    #Create KDEJson File
    new_kdejson=KDEJsonv2(assets=[new_kdeasset],vuln_defs=temp_kde_vuln_def)
    await async_write_file(full_kde_output
                     ,acsalert
                     ,new_kdejson)
   
# Get Startup Information
@app.on_event("startup")
async def startup_event():
    '''Startup Function'''
    logger.info("Starting up ACS/Kenna Integration Service")
    global instance_hostname  # pylint: disable=global-statement
    instance_hostname = getenv('HOSTNAME')


@app.get("/")
async def read_root():
    '''Application'''
    logger.info("Root Url '/' was Called")
    return {"Application": "Integration Service for Red Hat Advanced Cluster Security Service"}

@app.get("/health")
async def read_root():
    '''Application Health URL'''
    logger.info("Health Url was Called")
    return {"status": "OK"}

@app.post("/recieve_acs_vuln_alert_load")
async def determine_metadata(request: Request):
    global count
    json_temp=await request.json()
    json_formatted_str = json.dumps(json_temp, indent=2)
    print(f"\n")
    print(json_formatted_str)
    f = open("{}/example-{}.json".format(full_acs_output,count), "a")
    f.write(json_formatted_str)
    f.close()
    print(f"\n")
    count+=1
    return {"status": "OK"}

@app.post("/recieve_acs_vuln_alert")
async def determine_metadata(response: Response,request: Request,return_flag:str=None,alert: ACSAlert=Body(embed=True)):
    alert.acs_instance_ip=request.client.host
    await write_out_kde(alert)
    if return_flag == "message":
        return alert.json(include={'violations'})
    if return_flag == "all":
        return alert.json()
    return {"status": "OK"}

@app.get("/obtain_kde_output_files")
async def obtain_kde_files(kdealert:KDEJsonv2=None):
    return None
