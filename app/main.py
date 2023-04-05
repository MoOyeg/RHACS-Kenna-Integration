# pylint: disable=invalid-name
'''
Version 1: Prototype
'''

from asyncio import get_event_loop,create_task,Lock as AsyncLock,sleep as AsyncSleep
from concurrent.futures import ThreadPoolExecutor
from logging import getLogger, config
from os import getenv
from typing import Union,TypeVar, Generic  # pylint: disable=import-error
from pydantic import BaseModel,Extra  # pylint: disable=import-error
from fastapi import FastAPI,Request,Body,Response,BackgroundTasks # pylint: disable=import-error
from fastapi.responses import JSONResponse
from pathlib import Path, _ignore_error as pathlib_ignore_error
from fastapi.encoders import jsonable_encoder
from os import path,pardir,mkdir
from sys import exit
from aiofiles import os as async_os,open as async_open
from .config import settings
import json ,re
from dateutil import parser as dateutil_parser
from datetime import timezone,timedelta,datetime


#Class Definitions
#--------------------------------------------------------------------------------------------------
class KDEVulnDef(BaseModel):
    """KDE Vulnerability Definition"""
    scanner_type: str | None
    cve_identifiers: str | None
    wasc_identifiers: str | None
    cwe_identifiers: str | None
    name: str | None
    description: str | None
    solution: str = ""

class HashableKDEFinding(BaseModel):
    """Subclass of BaseModel that is hashable for KDEFinding"""
    def __hash__(self):  # make hashable BaseModel subclass
        """Hash function for KDEFinding, used for finding unique findings"""
        return hash((type(self),)                    
                    + tuple(self.scanner_identifier) 
                    + tuple(self.scanner_type)
                    + tuple(self.vuln_def_name))
        
class KDEFinding(HashableKDEFinding):
    scanner_identifier: str
    scanner_type: str
    created_at: str | None
    due_date: str | None
    last_seen_at: str
    severity: int | None
    triage_state: str | None	
    additional_fields: list | None
    vuln_def_name: str

class HashableKDEVuln(BaseModel):
    """Subclass of BaseModel that is hashable for KDEVuln"""
    def __hash__(self):  # make hashable BaseModel subclass
        return hash((type(self),) 
                    + tuple(self.scanner_identifier) 
                    + tuple(self.scanner_type)
                    + tuple(self.last_seen_at)
                    + tuple(self.vuln_def_name))
        
class KDEVuln(HashableKDEVuln):
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

class HashableKDEAsset(BaseModel):
    def __hash__(self):  # make hashable BaseModel subclass
        """Hash function for KDEAsset, used for finding unique assets"""
        return hash((type(self),) 
                    + tuple(self.external_id or "") 
                    + tuple(self.file or "")
                    + tuple(self.container_id or ""))
    
  
class KDEAsset(HashableKDEAsset,extra=Extra.allow):
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
    vulns: list[KDEVuln] 
    findings: list[KDEFinding] | None

class AppModel(BaseModel): 
  def dict(self, *args, **kwargs):
    if kwargs and kwargs.get("exclude_none") is not None:
      kwargs["exclude_none"] = True
      return BaseModel.dict(self, *args, **kwargs)
       
class KDEJsonv2(AppModel):
    skip_autoclose: bool = False
    version: int = 2
    assets: list[KDEAsset]
    reset_tags: bool = False
    vuln_defs: list[KDEVulnDef] | None
   
class ACSViolations(BaseModel):
    message: str
    
class ACSImageDetails(BaseModel):
    registry: str | None
    remote: str | None
    fullName: str | None
    
class ACSImage(BaseModel):
    id: str | None = None
    name: ACSImageDetails

class ACSContainer(BaseModel):
    name: str
    image: ACSImage
    notPullable: str | None
    isClusterLocal: str | None

class ACSDeployment(BaseModel):
    '''Affected RHACS Deployment as received from Vulnerability Data'''
    id: str
    name: str
    type: str | None
    namespace: str
    namespaceId: str
    labels: dict | None = None
    clusterId: str
    clusterName: str
    containers: list[ACSContainer]
    annotations: dict | None = None
    inactive: str | None

class ACSPolicy(BaseModel):
    '''Policy Information for Policy generating this Violation'''
    id: str
    name: str
    categories: list | None
    lifecycleStages: list[str]| None
    severity: str | None
    notifiers: list | None
    lastUpdated: str
    SORTName: str | None
    SORTLifecycleStage: str | None
    policyVersion: str | None
    policySections: list | None
    description: str | None
    rationale: str | None
    remediation: str | None
    disabled: str | None
    eventSource: str | None
    exclusions: list | None
    scope: list | None
    categories: list[str] | None
    severity: str | None
    enforcementActions: str | None
    mitreAttackVectors: str | None
    criteriaLocked: str | None
    mitreVectorsLocked: str | None
    isDefault: str | None 
    
class ACSAlert(BaseModel,extra=Extra.allow):  # pylint: disable=too-few-public-methods
    '''Class For Alert Information from RHACS'''
    id: str
    policy: ACSPolicy | None
    clusterId: str
    clusterName: str
    namespace: str
    namespaceId: str
    deployment: ACSDeployment
    resource : list | None
    violations: list[ACSViolations]
    time: str
    firstOccurred: str
    lifecycleStage: str | None
    resolvedAt: str | None
    state: str | None
    snoozeTill: str | None
    enforcement: dict | None = None

class KDEClusterMemory():
    """Class Container for all KDEJsonv2 Objects we are managing in Memory and aggregating at the cluster level"""
    _initalized = False
    _lock = AsyncLock()
    #Dict that stores all the kde_json objects we are managing state for
    kde_json_dict = {}
    #Dict that stores clusterid to asset hash's
    kde_json_dict_cluster = {}  
    #Dict that stores the mapping KDE Assets(Deployment) using their hash(asset+cluster_id) to assets
    kde_json_dict_asset = {}
    #Dict that stores the mapping KDE Assets(Deployment) using their hash(asset+cluster_id) to to a list of which alert_ids they were recieved from
    kde_json_dict_asset_alert_id = {}
    #Dict that stores the last time we recieved a particular alert_id
    kde_json_dict_alert_id__lasttime = {}
    kde_json_dict_cluster_name = {}
       
    @classmethod
    async def return_asset_hash(cls,asset:KDEAsset,cluster_id:str) -> str:
        """Return a hash of the asset and cluster_id"""
        logger.debug(f"return_asset_hash({asset},{cluster_id})")
        return str(hash(asset + cluster_id))

    @classmethod
    async def return_asset_exists_by_hash(cls,input_asset_hash:str) -> bool:
        """Return a hash of the asset and cluster_id"""
        logger.debug(f"return_asset_exists_by_hash({input_asset_hash})")
        if input_asset_hash in cls.kde_json_dict_asset.keys():
            return True  
        return False
    
    @classmethod
    async def return_kde_exists_by_cluster_id(cls,cluster_id:str) -> bool:
        """Return True if a kde_json exists for a given cluster_id"""
        logger.debug(f"return_kde_exists_by_cluster_id({cluster_id})")
        if cluster_id in cls.kde_json_dict.keys():
            return True
        else:
            return False
 
    @classmethod
    async def return_kde_by_cluster_id(cls,cluster_id:str) -> KDEJsonv2:
        """Return a kde_json by cluster_id"""
        logger.debug(f"return_kde_by_cluster_id({cluster_id})")
        return cls.kde_json_dict.get(cluster_id)
    
    @classmethod
    async def return_asset_alert_id_list(cls,asset_hash:str) -> list[str]:
        """Return a list of AlertIDs for a given asset_id"""
        logger.debug(f"return_asset_alert_id_list({asset_hash})")
        return cls.kde_json_dict_asset_alert_id.get(asset_hash)
    
    @classmethod
    async def can_be_autoclosed(cls,asset_hash:str) -> bool:
        logger.debug(f"can_be_autoclosed - Checking if we need to autoclose {asset_hash}")
        if asset_hash in cls.kde_json_dict_asset_alert_id.keys():                                                        
            #Get the most recent alert from RHACS for this asset
            try:
                alert_id_list=cls.kde_json_dict_asset_alert_id[asset_hash]
                most_recent_alert_id = ""
                alert_id_lasttime = ""
                #In case more than one alerts are present for the same asset, we will use the most recent one
                for alert_id in alert_id_list:
                    if most_recent_alert_id == "":
                        most_recent_alert_id = alert_id
                    elif cls.kde_json_dict_alert_id__lasttime[most_recent_alert_id] < cls.kde_json_dict_alert_id__lasttime[alert_id]:
                        most_recent_alert_id = alert_id                                                                  
                    alert_id_lasttime=cls.kde_json_dict_alert_id__lasttime[most_recent_alert_id]
                    
                if int((datetime.now(tz=None)-alert_id_lasttime).total_seconds()) > settings.acs_autoclose_time:
                    logger.debug(f"Autoclose logic will be applied for asset {asset_hash}")
                    return True
            except ValueError:
                    logger.error("Could not apply autoclose logic")
        return False
    
    @classmethod 
    async def add_new_kde_by_cluster_id(cls,acsalert:ACSAlert,kdeinput:KDEJsonv2):
        """Add a new kde_json by cluster_id because it does not exist"""
        logger.debug(f"add_new_kde_by_cluster_id({acsalert.clusterId})")
        if not await cls.return_kde_exists_by_cluster_id(acsalert.clusterId):
            async with cls._lock: 
                               
                #Add the new kde_json_dict
                logger.debug(f"add_new_kde_by_cluster_id({acsalert.clusterId}) - got lock")
                cls.kde_json_dict.update({acsalert.clusterId:kdeinput})
                logger.debug(f"add_new_kde_by_cluster_id({acsalert.clusterId}) - Added new kde_json_dict")
                                
                #Update the AlertID Mapping to the list of Assets(Deployments)
                try:                    
                    for asset in kdeinput.assets:
                        new_hash = cls.return_asset_hash(asset,acsalert.clusterId)
                        cls.kde_json_dict_asset.update({new_hash:asset})
                        if new_hash in cls.kde_json_dict_asset_alert_id.keys():
                            cls.kde_json_dict_asset_alert_id[new_hash].append(acsalert.id)
                            cls.kde_json_dict_cluster[acsalert.clusterId].append(new_hash)                            
                        else:
                            cls.kde_json_dict_asset_alert_id[new_hash] = [acsalert.id]
                            cls.kde_json_dict_cluster.update({acsalert.clusterId:[new_hash]})  
                except Exception as e:
                    logger.error(f"add_new_kde_by_cluster_id({acsalert.clusterId}) - Error adding asset to kde_json_dict_asset_alert_id: {e}")
                
                #Update the last time we recieved this particular alert_id
                try:
                    if acsalert.id in cls.kde_json_dict_alert_id__lasttime.keys():
                        cls.kde_json_dict_alert_id__lasttime[acsalert.id] = datetime.now()
                    else:
                        cls.kde_json_dict_alert_id__lasttime.update({acsalert.id:datetime.now()})
                except Exception as e:
                    logger.error(f"add_new_kde_by_cluster_id({acsalert.clusterId}) - Error adding alert_id to kde_json_dict_alert_id__lasttime: {e}")                 
            logger.debug(f"add_new_kde_by_cluster_id({acsalert.clusterId}) - released lock")
        else:
            #This means we already have a kde_json for this cluster_id
            logger.error(f"add_new_kde_by_cluster_id({acsalert.clusterId}) - kde_json already exists")

    @classmethod 
    async def add_new_asset_by_alert(cls,asset:KDEAsset,acsalert:ACSAlert):
        """Add a new asset by asset_hash because it does not exist"""
        asset_hash = await cls.return_asset_hash(asset,acsalert.clusterId)
        logger.debug(f"add_new_asset_by_cluster_id({asset_hash})") 
               
        if not await cls.return_asset_exists_by_hash(asset_hash):
            async with cls._lock:
                #Add the new asset
                logger.debug(f"add_new_asset_by_hash({asset_hash}) - got lock")
                cls.kde_json_dict_asset.update({asset_hash:asset})
                cls.kde_json_dict_cluster[acsalert.clusterId].append(asset_hash)            
                #TODO: Add the new asset to the kde_json_dict_asset_alert_id
                logger.debug(f"add_new_asset_by_hash({asset_hash}) - Added new asset")
            logger.debug(f"add_new_asset_by_hash({asset_hash}) - released lock")
        else:
            #This means we already have a kde_json for this cluster_id
            #TODO redirect to update_asset_by_hash
            logger.error(f"add_new_asset_by_hash({asset_hash}) - asset already exists")
    
    
    # @classmethod
    # async def delete_kde_by_cluster_id(cls,acsalert:ACSAlert):
    #     """Delete a kde_json by cluster_id"""
    #     logger.debug(f"delete_kde_by_cluster_id({acsalert.clusterId})")
    #     if await cls.return_kde_exists_by_cluster_id(acsalert.clusterId):
    #         async with cls._lock:
    #             logger.debug(f"delete_kde_by_cluster_id({acsalert.clusterId}) - got lock")
    #             try:
    #                 cls.kde_json_dict.pop(acsalert.clusterId)
    #             except KeyError:
    #                 logger.error(f"delete_kde_by_cluster_id({acsalert.clusterId}) - KeyError")
    #             try:
    #                 cls.kde_json_dict_alert_id.pop(acsalert.clusterId)            
    #             except KeyError:
    #                 logger.error(f"delete_kde_by_cluster_id({acsalert.clusterId}) - KeyError")                    
    #             logger.debug(f"delete_kde_by_cluster_id({acsalert.clusterId}) - deleted from kde_json_dict")
    #         logger.debug(f"delete_kde_by_cluster_id({acsalert.clusterId}) - released lock")
    #     else:
    #         logger.debug(f"delete_kde_by_cluster_id({acsalert.clusterId}) - kde_json does not exist")
        
    # @classmethod
    # async def replace_kde_by_cluster_id(cls,acsalert:ACSAlert,kdeinput:KDEJsonv2):
    #     """Update a kde_json by cluster_id"""
    #     logger.debug(f"replace_kde_by_cluster_id({acsalert.clusterId})")
    #     async with cls._lock:
    #         logger.debug(f"replace_kde_by_cluster_id({acsalert.clusterId}) - got lock")
    #         #Replace KDE Object
    #         try:
    #             cls.kde_json_dict.pop(acsalert.clusterId)
    #         except KeyError:
    #             logger.error(f"replace_kde_by_cluster_id({acsalert.clusterId}) - KeyError")
    #         cls.kde_json_dict.update({acsalert.clusterId:kdeinput})
    #         #Replace Alert ID
    #         try:
    #             temp_dict = cls.kde_json_dict_alert_id[acsalert.clusterId]
    #             temp_dict.append(acsalert.id)
    #         except KeyError:
    #             logger.error(f"replace_kde_by_cluster_id({acsalert.clusterId}) - KeyError when updating alert_id's")  
    #         logger.debug(f"replace_kde_by_cluster_id({acsalert.clusterId}) - updated kde_json_dict")
    #     logger.debug(f"replace_kde_by_cluster_id({acsalert.clusterId}) - released lock")
    
    @classmethod
    async def receive_kdejson(cls,kdeinput:KDEJsonv2,acsalert:ACSAlert) -> None:
        """Add a new KDEJsonv2 Object to the container from outside the class"""
        logger.debug(f"receive_kdejson({acsalert.id})")
        
        #Check if the cluster_id already exists     
        if await cls.return_kde_exists_by_cluster_id(acsalert.clusterId):
            logger.info(f"KDEJsonv2 for cluster {acsalert.clusterId} already exists will update")

            #Temp lists to hold the assets we need to add, remove, and update
            temp_autoclose_add_assets = []
            temp_autoclose_remove_assets = []
            temp_input_assets = []
            temp_tomerge_assets = []
            temp_new_assets = []
            temp_kde_vuln_defs = []
                
            #Parse the assets from the alert
            check_empty_assets = True
            for input_asset in kdeinput.assets:
                check_empty_assets = False
                input_asset_hash = await cls.return_asset_hash(input_asset,acsalert.clusterId)
                if await cls.return_asset_exists_by_hash(input_asset_hash):
                    #This means there is an already existing asset that matches the one we are trying to add
                    logger.debug(f"Found matching asset {input_asset}")                                        
                    temp_input_assets.append(input_asset)
                    # temp_tomerge_assets.append(previous_asset)
                else:
                    #This means there is no existing asset that matches the one we are trying to add
                    logger.debug(f"Did not find an existing asset for {input_asset} will add it")
                    temp_new_assets.append(input_asset)
                    
            if check_empty_assets:
                #There were no assets we parsed from the alert, really should not happen
                logger.warning(f"receive_kdejson({acsalert.id}) - No assets found in kdeinput")
                
                #Filter though Vulnerability Definitions           
                # if len(kdeinput.vuln_defs) > 0:        
                #     for vuln_def in kdeinput.vuln_defs: 
                #         new_vuln=True                   
                #         for previous_vuln_def in previous_kde.vuln_defs:                            
                #             if vuln_def.name == previous_vuln_def.name:
                #                 #Don't add vuln def if it already exists
                #                 new_vuln=False
                #         if not new_vuln:
                #             temp_kde_vuln_defs.append(vuln_def)

            #Decide how to handle the asset
                    
            for input_asset in temp_input_assets:
                logger.debug(f"Updating asset {input_asset}")
                await cls.add_new_asset_by_alert(input_asset,acsalert)
                logger.debug(f"Done Updating asset {input_asset}")
                    
                # #Replacing Assets that are expired based on autoclose logic
                # logger.debug(f"Removing assets temp_autoclose_remove_assets and adding assets temp_autoclose_add_assets based on autoclose logic")
                # for remove_asset in temp_autoclose_remove_assets:
                #     previous_kde.assets.remove(remove_asset)
                # for input_asset in temp_autoclose_add_assets:
                #     previous_kde.assets.append(input_asset)                   
                        
                # #Add New Assets
                # for new_asset in temp_add_assets:
                #     previous_kde.assets.append(new_asset)
                    
                # #Add New Vuln Defs
                # for vuln_def in temp_kde_vuln_defs:
                #     previous_kde.vuln_defs.append(vuln_def)                
             
        #Cluster_id does not exist so add it
        else:
            logger.info(f"KDEJsonv2 for cluster {acsalert.clusterId} does not exist will create")
            await cls.add_new_kde_by_cluster_id(acsalert,kdeinput)

#------------------------------------------------------------------------------------------------

#App Init and Global Variables
#------------------------------------------------------------------------------------------------
#Logging
log_file_path = path.join(path.dirname(path.abspath(__file__)), 'logging.conf')
config.fileConfig(log_file_path, disable_existing_loggers=False)
logger = getLogger("logger_root")

#Output Folder Directories
kde_output=settings.kde_output_folder
acs_output=settings.acs_output_folder
parent_dir=path.abspath(path.join(path.dirname(path.abspath(__file__)), pardir))
full_kde_output=path.join(parent_dir,kde_output)
full_acs_output=path.join(parent_dir,acs_output)

#Other Variables
scanner_type="redhat_rhacs_scanner"
bulk_count_alerts=0
count_alerts=0
continous_loop_task = None

#Declare App as a FastApi Object
app = FastAPI()

#Instance Hostname is global
instance_hostname = ""
#------------------------------------------------------------------------------------------------
#Methods and Routes
#------------------------------------------------------------------------------------------------

def sync_write_file(fullfilepath,acsalert=None,kdeobject=None,content=None,mode="w+"):
    """ Method to synchonously write to Files"""
    pass
    
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

async def async_write_file(fullfilepath,object=None,content=None,mode="w+"):
    """ Method to Asynchonously write Objects to Files,Method Only writes JSON Encodable Objects to Files"""
    count=1
    tempfullfilepath=fullfilepath
    
    if object is None and content is None:
        logger.error("Must provide either an object or content to write to file")
    if mode != "w" and mode != "w+":
        while await path_exists(f"{tempfullfilepath}.json"):        
            tempfullfilepath='{}_{}'.format(fullfilepath,count)
            count += 1
    if mode == "w" or mode == "w+":
        tempfullfilepath='{}'.format(fullfilepath)                
    filehandle = await async_open(f"{tempfullfilepath}.json", mode=mode)
    if object is not None:
        await filehandle.write(json.dumps(jsonable_encoder(object),indent=2))
    elif content is not None:
        await filehandle.write(json.dumps(content,indent=2))
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

async def initiate_kde_conversion(acsalert:ACSAlert):
    """ Determine then write received info from ACS Alert to KDE File""" 
    logger.info("Initiating KDE Conversion for {}".format(acsalert.id))
           
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
            logger.debug("Added Vuln Def {} to KDE".format(cvss_name))
        
        if cvss_name not in temp_kde_vuln_name:
            new_vuln = KDEVuln(scanner_identifier = cvss_name
                               ,scanner_type = await return_scanner_type()
                               ,scanner_score = cvss_score
                               ,last_seen_at = acsalert.time
                               ,created_at=acsalert.firstOccurred
                               ,status = "open"
                               ,vuln_def_name = cvss_name)
            temp_kde_vuln.append(new_vuln)
            temp_kde_vuln_name.append(cvss_name)
            logger.debug("Added Vuln {} to KDE".format(cvss_name))
            
            new_finding= KDEFinding(scanner_identifier = cvss_name
                               ,scanner_type = await return_scanner_type()
                               ,scanner_score = cvss_score
                               ,last_seen_at = acsalert.time
                               ,created_at=acsalert.firstOccurred
                               ,vuln_def_name = cvss_name)
            temp_kde_finding.append(new_finding)
            logger.debug("Added Finding {} to KDE".format(cvss_name))            

    if settings.aggregation_logic.lower() == "cluster_level":
        #Will attempt to create a KDE Output File Per Cluster
        new_kdeasset=KDEAsset(file=acsalert.clusterName
                            ,container_id=acsalert.deployment.id
                            ,external_id=acsalert.id
                            ,vulns=temp_kde_vuln
                            ,findings=temp_kde_finding)
        logger.debug("Created KDE Asset for Deployment {}".format(acsalert.deployment.id))
        
        #Pass Deployment Labels to Asset Tags
        if acsalert.deployment.labels is not None:
            if new_kdeasset.tags is None:
                new_kdeasset.tags = []
            for key in acsalert.deployment.labels:
                new_kdeasset.tags.append("{}:{}".format(key,acsalert.deployment.labels[key]))
            new_kdeasset.tags = list(new_kdeasset.tags)
        logger.debug("Added Deployment Labels to KDE Asset for Deployment {}".format(acsalert.deployment.id))   

        new_kdejson=KDEJsonv2(assets=list([new_kdeasset]),vuln_defs=temp_kde_vuln_def)
        logger.debug("Created KDE Json for Deployment {}".format(acsalert.deployment.id))
        
        await KDEClusterMemory.receive_kdejson(new_kdejson,acsalert)
        # for item in KDEClusterMemory.kde_json_dict.items():
        #     await async_write_file(f"{full_kde_output}/{item[0]}",object=item[1],content=None,mode="w")
        logger.debug("Added KDE Json for Deployment {} to Container".format(acsalert.deployment.id))

async def continous_kde_output():
    '''Continuous KDE Output Coroutine'''
    while True:
        logger.info("Starting KDE Output Continous Print Loop")
        for item in KDEClusterMemory.kde_json_dict.items():
            logger.debug("Starting KDE Output Continous Print Loop for {}".format(item[0]))
            await async_write_file(f"{full_kde_output}/{item[0]}",object=item[1],content=None,mode="w")
        await AsyncSleep(settings.kde_output_timer)
        
# Get Startup Information
@app.on_event("startup")
async def startup_event():
    '''Startup Function'''
    logger.info("Starting up ACS/Kenna Integration Service")
    global instance_hostname  #pylint: disable=global-statement
    global continous_loop_task #pylint: disable=global-statement
    
    instance_hostname = getenv('HOSTNAME')
    logger.info("Instance Hostname: {}".format(instance_hostname))
    
    #Checking KDE Output Directory Exists
    if not await path_exists(full_kde_output):
        logger.error(f"KDE Output Directory - {full_kde_output} does not exist, will attempt creating it")
        try:
            mkdir(full_kde_output)
        except:
            logger.error(f"KDE Output Directory - {full_kde_output} could not be created, please create it manually")
            exit(1)
    logger.debug(f"KDE Output Directory - {full_kde_output} exists")

    #Checking ACS Output Directory Exists
    if not await path_exists(full_acs_output):
        logger.error(f"ACS Example Output Directory - {full_acs_output} does not exist, will attempt creating it")
        try:
            mkdir(full_acs_output)
        except:
            logger.error(f"ACS Example Output Directory - {full_acs_output} could not be created, please create it manually")
            exit(1)
            
    #Start Continous KDE Output
    continous_loop_task=create_task(continous_kde_output())
    
    logger.debug(f"ACS Example Output Directory - {full_acs_output} exists")  
    logger.info("Startup Complete")

@app.get("/")
async def root():
    '''Application'''
    logger.info("Root Url '/' was Called")
    return {"Application": "Integration Service for Red Hat Advanced Cluster Security Service"}

@app.get("/health")
async def health():
    '''Application Health URL'''
    logger.debug("Health Url '/health' was Called")
    return {"status": "OK"}

@app.post("/load_bulk_acs_alerts")
async def determine_metadata_bulk(request: Request):
    """Function not meant for normal use, used to load bulk alerts into the system for testing purposes"""
    global bulk_count_alerts #pylint: disable=global-statement
    global full_acs_output #pylint: disable=global-statement
    
    bulk_count_alerts+=1
    json_temp = await request.json()
    json_formatted_str = json.dumps(json_temp, indent=2)
    logger.info("{}".format(json.dumps(json_temp,indent=2)))    
    await async_write_file(f"{full_acs_output}/acs_alert_example",None,json_temp,"a")
    return {"status": "OK"}

@app.post("/receive_acs_vuln_alert")
async def determine_metadata(background_tasks: BackgroundTasks,response: Response,request: Request,return_flag:str=None,alert: ACSAlert=Body(embed=True)):
    logger.info("Recieved Alert with ID: {}".format(alert.id))
    global count_alerts #pylint: disable=global-statement
    alert.acs_instance_ip=request.client.host
    logger.debug("Alert with ID: {} was received from IP: {}".format(alert.id,alert.acs_instance_ip))
    count_alerts += 1
    
    if return_flag is not None:
        await initiate_kde_conversion(alert)
        if return_flag == "message":
            logger.debug("Returning Message for Alert with ID: {}".format(alert.id))
            
            return alert.json(include={'violations'})
        if return_flag == "all":
            logger.debug("Returning Alert for Alert with ID: {}".format(alert.id))
            return alert.json()
    else:
        logger.debug("Adding Alert with ID: {} to Background Tasks".format(alert.id))
        background_tasks.add_task(initiate_kde_conversion,alert)
        logger.debug("Added Alert with ID: {} to Background Tasks".format(alert.id))
        return {"status": "Recieved Alert with ID: {}".format(alert.id)}


@app.get("/obtain_kde_output_files")
async def obtain_kde_files(kdealert:KDEJsonv2=None):
    return None

