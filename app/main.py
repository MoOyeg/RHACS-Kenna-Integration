# pylint: disable=invalid-name
'''
Version 1: Prototype
'''

from asyncio import get_event_loop
from concurrent.futures import ThreadPoolExecutor
from logging import getLogger, config
from os import getenv
from typing import Optional  # pylint: disable=import-error
from pydantic import BaseModel  # pylint: disable=import-error
from fastapi import FastAPI,Request,Body, Response # pylint: disable=import-error
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from os import path
import json

class ACSViolations(BaseModel):
    message: str
    
class ACSImageDetails(BaseModel):
    registry: str
    remote: str
    fullName: str
    
class ACSImage(BaseModel):
    id: str
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

       
json_object = []
count = 0
# setup loggers

log_file_path = path.join(path.dirname(path.abspath(__file__)), 'logging.conf')
config.fileConfig(log_file_path, disable_existing_loggers=False)
logger = getLogger("logger_root")

# Declare App as a FastApi Object
app = FastAPI()

# Instance Hostname is global
instance_hostname = ""

# TO-DO Streamline determine functions into 1(Probably a custom decorator)

# Get Startup Information
@app.on_event("startup")
async def startup_event():
    '''Startup Function'''
    logger.info("Starting up Integration Service")
    global instance_hostname  # pylint: disable=global-statement
    instance_hostname = getenv('HOSTNAME')


@app.get("/")
async def read_root():
    '''Application'''
    logger.info("Root Url '/' was Called")
    return {"Application": "Integration Service for Red Hat Advanced Cluster Security Service"}


@app.post("/recieve_acs_vuln_alert")
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

@app.post("/recieve_acs_vuln_alert_test")
async def determine_metadata(response: Response,request: Request,alert: ACSAlert=Body(embed=True)):
    if response.status_code == 422:
        json_temp=await request.json()
        json_formatted_str = json.dumps(json_temp, indent=2)
        print(f"\n")
        print(json_formatted_str)
        print(f"\n")
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
    
# @app.post("/recieve_acs_vuln_alert")
# async def determine_metadata(alert: ACSAlert = Body(embed=True)):
#     '''determine cloud'''
#     logger.info("/metadata path was called")
#     # json_temp=await request.json()
#     # global json_object
#     # payload: dict = Body(...)
#     # json_object.append(json_temp)
#     print(alert)
#     return {"status": "OK"}
#     # if metadata.cloudname == "unknown":
#     #     result = False
#     #     if q is None:
#     #         for determine_function in determine_cloud_functions_list:
#     #             result = await determine_function()
#     #             if result[0] is True:
#     #                 response_data = result[1]()
#     #                 metadata.cloudname = result[2]
#     #                 metadata.hostname = response_data["hostname"]
#     #                 metadata.region = response_data["region"]
#     #                 metadata.instance_type = response_data["instanceType"]
#     #                 metadata.availability_zone = response_data["availability_zone"]
#     #                 break
#     #         return JSONResponse(metadata.todict())
#     # else:
#     #     return JSONResponse(metadata.todict())