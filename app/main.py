# pylint: disable=invalid-name
'''
Version 1: Prototype
'''

from asyncio import get_event_loop
from concurrent.futures import ThreadPoolExecutor
from logging import getLogger, config
from os import getenv
from typing import Optional  # pylint: disable=import-error
from pydantic import BaseModel,Extra  # pylint: disable=import-error
from fastapi import FastAPI,Request,Body,Response # pylint: disable=import-error
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from os import path
import json

class KDEVulnDef(BaseModel):
    scanner_type: str
    cve_identifiers: str | None
    wasc_identifiers: str | None
    cwe_identifiers: str | None
    name: str
    description: str
    solution: str

class KDEFinding(BaseModel):
    scanner_identifier: str
    scanner_type: str
    created_at: str | None
    due_date: str | None
    last_seen_at: str
    severity: int | None
    triage_state: str	 	
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
    port: int 
    vuln_def_name: str    

class KDElocator_field(BaseModel):
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

class KDEAsset(BaseModel,extra=Extra.allow):
    # KDElocator_field: KDElocator_field
    application: str | None
    tags: list[str] | None
    owner: str | None
    os: str | None
    os_version: str | None
    priority: str | None
    asset_type: str | None
    vulns: str | None
    findings: str | None
      
class KDEJsonv2(BaseModel):
    skip_autoclose: bool = False
    version: int = 2
    assets: list[KDEAsset]
    reset_tags: bool = False
    #Commenting to allow parsing at the moment,needs work.
    # vulns: list[KDEvuln]
    # findings:  list[KDEFinding]
    
   

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
    
class ACSAlert(BaseModel):  # pylint: disable=too-few-public-methods
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

log_file_path = path.join(path.dirname(path.abspath(__file__)), 'logging.conf')
config.fileConfig(log_file_path, disable_existing_loggers=False)
logger = getLogger("logger_root")
count=0
# Declare App as a FastApi Object
app = FastAPI()

# Instance Hostname is global
instance_hostname = ""

#Write Output To KDE
async def write_out_kde(acsalert:ACSAlert):
    """ Write Received ACS Alert to KDE File"""
    
    #Create Deployment As KDE Assets
    new_kdeasset=KDEAsset(external_id=acsalert.deployment.id)
    if acsalert.deployment.labels is not None:
        if new_kdeasset.tags is None:
            new_kdeasset.tags = []
        for key in acsalert.deployment.labels:
            new_kdeasset.tags.append("{}:{}".format(key,acsalert.deployment.labels[key]))
    new_kdejson=KDEJsonv2(assets=[new_kdeasset])
    
    f = open('./kde_output/{}.json'.format(acsalert.deployment.id),"a")  
    f.write(json.dumps(jsonable_encoder(new_kdejson),indent=2))
    f.close()
    
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
    f = open("./json_examples/example-{}.json".format(count), "a")
    f.write(json_formatted_str)
    f.close()
    print(f"\n")
    count+=1
    return {"status": "OK"}

@app.post("/recieve_acs_vuln_alert")
async def determine_metadata(response: Response,request: Request,alert: ACSAlert=Body(embed=True)):
    await write_out_kde(alert)
    return {"status": "OK"}

def register_exception(app: FastAPI):
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):

        exc_str = f'{exc}'.replace('\n', ' ').replace('   ', ' ')
        # or logger.error(f'{exc}')
        logger.error(request, exc_str)
        content = {'status_code': 10422, 'message': exc_str, 'data': None}
        print(content)
        return JSONResponse(content=content, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)
    