# pylint: disable=invalid-name
'''
Version 1: Prototype
'''

from asyncio import get_event_loop, create_task, Lock as AsyncLock, sleep as AsyncSleep
from collections import OrderedDict
from logging import getLogger, config
from os import getenv
from requests.exceptions import HTTPError, ConnectionError,Timeout
from typing import Union, TypeVar, Generic  # pylint: disable=import-error
from pydantic import BaseModel, Extra  # pylint: disable=import-error
from fastapi import FastAPI, Request, Body, Response, BackgroundTasks,status  # pylint: disable=import-error
from starlette.background import BackgroundTasks as StarletteBackgroundTasks
from fastapi.responses import JSONResponse
from pathlib import Path, _ignore_error as pathlib_ignore_error
from fastapi.encoders import jsonable_encoder
from os import path, pardir, mkdir
from sys import exit
from aiofiles import os as async_os, open as async_open
from .config import settings
import json
import re
import copy
from dateutil import parser as dateutil_parser
from datetime import timezone, timedelta, datetime
from .acs_alert_request import get_acs_alert, get_rhacs_health


# Class Definitions
# --------------------------------------------------------------------------------------------------
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


class KDEAsset(HashableKDEAsset, extra=Extra.allow):
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
    lifecycleStages: list[str] | None
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
    enforcementActions: list | None
    mitreAttackVectors: list | None
    criteriaLocked: str | None
    mitreVectorsLocked: str | None
    isDefault: str | None


class ACSAlert(BaseModel, extra=Extra.allow):  # pylint: disable=too-few-public-methods
    '''Class For Alert Information from RHACS'''
    id: str
    policy: ACSPolicy | None
    clusterId: str
    clusterName: str
    namespace: str
    namespaceId: str
    deployment: ACSDeployment
    resource: list | None
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
    # Dict that stores all the kde_json objects we are managing state for
    store_cluster_id_to_kde_json_output_map = {}
    # Dict that stores clusterid to asset hash's
    store_cluster_id_to_asset_hash_list_map = {}
    # Dict that stores the mapping KDE Assets(Deployment) using their hash(asset+cluster_id) to assets
    store_asset_hash_to_asset_value_map = {}
    # Dict that stores the mapping KDE Assets(Deployment) using their hash(asset+cluster_id) to to a list of which alert_ids they were recieved from
    store_asset_hash_to_alert_id_list_map = {}
    #Dict that stores alert_id to asset_hash match i.e alert_id to assets they provided us with
    store_alert_id_to_asset_hash_map={}
    # Dict that stores the last time we recieved a particular alert_id
    store_alert_id_to_lasttime_map = {}
    #Dict that stores cluster_id to cluster_name
    store_cluster_id_to_cluster_name_map = {}

    @classmethod
    async def update_store_alert_id_to_lasttime_map(cls, acsalert_id: str) -> bool:
        """Update the last time we recieved an alert_id"""
        if not cls._lock.locked():
            raise Exception("update_store_alert_id_to_lasttime_map() - Lock not locked, Function should only be called from within the lock")

        try:
            if acsalert_id in cls.store_alert_id_to_lasttime_map.keys():
                cls.store_alert_id_to_lasttime_map[acsalert_id] = datetime.now(
                )                
            else:
                cls.store_alert_id_to_lasttime_map.update(
                    {acsalert_id: datetime.now()})
        except Exception as e:
            logger.error(
                f"update_store_alert_id_to_lasttime_map({acsalert_id}) - Error adding alert_id to store_alert_id_to_lasttime_map: {e}")
            return False
        logger.debug("update_store_alert_id_to_lasttime_map() - Updated store_alert_id_to_lasttime_map")
        return True
    
    @classmethod
    async def update_store_alert_id_to_asset_hash_map(cls,acsalert_id: str, input_asset_hash: str,action:str=None) -> bool:
        """Update Alert_ID to the list of Alert Hashes it provided"""
        
        if not cls._lock.locked():
            raise Exception("update_store_alert_id_to_asset_hash_map() - Lock not locked, Function should only be called from within the lock")        
        
        if action == "remove".lower():
            logger.debug("update_store_alert_id_to_asset_hash_map() - Removing asset_hash from store_alert_id_to_asset_hash_map")
            try:
                if acsalert_id in cls.store_alert_id_to_asset_hash_map.keys():
                    cls.store_alert_id_to_asset_hash_map[acsalert_id].remove(input_asset_hash)
            except Exception as e:
                logger.error("update_store_alert_id_to_asset_hash_map() - Error removing asset_hash from store_alert_id_to_asset_hash_map: {e}")
                return False
            logger.debug("update_store_alert_id_to_asset_hash_map() - Removed asset_hash from store_alert_id_to_asset_hash_map")
            return True
        
        try:
            if acsalert_id in cls.store_alert_id_to_asset_hash_map.keys():
                cls.store_alert_id_to_asset_hash_map[acsalert_id].append(input_asset_hash)
            else:
                cls.store_alert_id_to_asset_hash_map.update({acsalert_id: [input_asset_hash]})
        except Exception as e:
            logger.error(
                f"update_store_alert_id_to_asset_hash_map({acsalert_id},{input_asset_hash}) - Error adding alert_id to store_alert_id_to_asset_hash_map: {e}")
            return False
        logger.debug("update_store_alert_id_to_asset_hash_map() - Added alert_id to store_alert_id_to_asset_hash_map")
        return True
    
    @classmethod
    async def update_store_cluster_id_to_cluster_name_map(cls, cluster_id: str, cluster_name: str) -> bool:
        """Update the cluster_id to cluster_name map"""
        if not cls._lock.locked():
            raise Exception("update_store_alert_id_to_asset_hash_map() - Lock not locked, Function should only be called from within the lock")
   
        try:
            logger.debug(f"update_store_cluster_id_to_cluster_name_map({cluster_id},{cluster_name})")
            if cluster_id not in cls.store_cluster_id_to_cluster_name_map.keys():
                cls.store_cluster_id_to_cluster_name_map.update({cluster_id: cluster_name})
            else:
                cls.store_cluster_id_to_cluster_name_map[cluster_id] = cluster_name
        except Exception as e:
            logger.errror(f"update_store_cluster_id_to_cluster_name_map({cluster_id},{cluster_name}) - Error adding cluster_id to store_cluster_id_to_cluster_name_map: {e}")
            return False
        logger.debug(f"update_store_cluster_id_to_cluster_name_map({cluster_id},{cluster_name})")
        return True
            
    @classmethod
    async def update_store_asset_hash_to_alert_id_list_map(cls, input_asset_hash: str, acsalert_id: str,action: str=None) -> bool:
        """Update the asset_hash to alert_id list map"""
        if not cls._lock.locked():
            raise Exception("update_store_asset_hash_to_alert_id_list_map() - Lock not locked, Function should only be called from within the lock")
        logger.debug(f"update_store_asset_hash_to_alert_id_list_map({input_asset_hash},{acsalert_id})")
        
        if action == "remove".lower():
            logger.debug("update_store_asset_hash_to_alert_id_list_map() - Removing alert_id from store_asset_hash_to_alert_id_list_map")
            try:
                cls.store_asset_hash_to_alert_id_list_map[input_asset_hash].remove(acsalert_id)
                if len(cls.store_asset_hash_to_alert_id_list_map[input_asset_hash]) == 0:
                    del cls.store_asset_hash_to_alert_id_list_map[input_asset_hash]
            except Exception as e:
                logger.error("update_store_asset_hash_to_alert_id_list_map() - Error removing alert_id from store_asset_hash_to_alert_id_list_map: {e}")
                return False
            return True
        
        try:
            if input_asset_hash in cls.store_asset_hash_to_alert_id_list_map.keys():
                cls.store_asset_hash_to_alert_id_list_map[input_asset_hash].append(acsalert_id)
            else:
                cls.store_asset_hash_to_alert_id_list_map.update({input_asset_hash: [acsalert_id]})
            logger.debug(f"update_store_asset_hash_to_alert_id_list_map({input_asset_hash},{acsalert_id})")
        except Exception as e:          
            logger.error(
                f"update_store_asset_hash_to_alert_id_list_map({input_asset_hash},{acsalert_id}) - Error adding alert_id to store_asset_hash_to_alert_id_list_map: {e}")
            return False                 
        return True
    
    @classmethod
    async def update_store_cluster_id_to_kde_json_output_map(cls, cluster_id: str, kdeinput: KDEJsonv2=None,asset: KDEAsset=None,action:str =None) -> bool:
        """Update the cluster_id to kde_input"""
        if not cls._lock.locked():
            raise Exception("update_store_cluster_id_to_kde_json_output_map() - Lock not locked, Function should only be called from within the lock")
        
        logger.debug(f"update_store_cluster_id_to_kde_json_output_map({cluster_id},{kdeinput})")
        
        if action == "remove".lower():
            if asset is not None:
                asset_hash = await cls.return_asset_hash(asset, cluster_id)
                logger.debug(f"update_store_cluster_id_to_kde_json_output_map() - Removing asset from kdeinput - asset_hash:{asset_hash} in cluster_id{cluster_id}")
                if await cls.return_asset_exists_by_hash(asset_hash):
                    try:
                        cls.store_cluster_id_to_kde_json_output_map[cluster_id].assets.remove(asset)
                    except Exception as e:
                        logger.error(f"update_store_cluster_id_to_kde_json_output_map({cluster_id},{asset_hash}) - Error removing asset from kdeinput: {e}")
                        return False   
                    logger.debug(f"update_store_cluster_id_to_kde_json_output_map() - Removed asset from kdeinput - asset_hash:{asset_hash} in cluster_id{cluster_id}")
                    return True
                    
            elif kdeinput is not None:
                logger.debug(f"update_store_cluster_id_to_kde_json_output_map() - Removing kdeinput - cluster_id{cluster_id}")
                if cluster_id in cls.store_cluster_id_to_kde_json_output_map.keys():
                    try:
                        del cls.store_cluster_id_to_kde_json_output_map[cluster_id]
                    except Exception as e:
                        logger.error(f"update_store_cluster_id_to_kde_json_output_map({cluster_id},{kdeinput}) - Error removing kdeinput: {e}")
                        return False   
                    logger.debug(f"update_store_cluster_id_to_kde_json_output_map() - Removed kdeinput - cluster_id{cluster_id}")
                    return True
        
        #If asset is not None, then add the asset to the kdeinput
        if asset is not None:
            asset_hash = await cls.return_asset_hash(asset, cluster_id)
            if not await cls.return_asset_exists_by_hash(asset_hash):
                try:
                    cls.store_cluster_id_to_kde_json_output_map[cluster_id].assets.append(asset)
                except Exception as e:
                    logger.error(f"update_store_cluster_id_to_kde_json_output_map({cluster_id},{kdeinput}) - Error adding asset to kdeinput: {e}")
                    return False   
                return True
       
        #Add new kdeinput
        try:
            if cluster_id not in cls.store_cluster_id_to_kde_json_output_map.keys():
                cls.store_cluster_id_to_kde_json_output_map.update({cluster_id: kdeinput})
                logger.debug(f"update_store_cluster_id_to_kde_json_output_map({cluster_id})") 
            else:
                logger.error(f"update_store_cluster_id_to_kde_json_output_map({cluster_id},{kdeinput}) - Cluster_id already exists in store_cluster_id_to_kde_json_output_map")
                return False
        except Exception as e:
            logger.error(
                f"update_store_cluster_id_to_kde_json_output_map({cluster_id},{kdeinput}) - Error adding cluster_id to store_cluster_id_to_kde_json_output_map: {e}")
            return False
        return True

    @classmethod
    async def update_store_asset_hash_to_asset_value_map(cls, input_asset_hash: str, asset: KDEAsset,action:str=None) -> bool:
        """Update the asset_hash to asset_value map"""
        if not cls._lock.locked():
            raise Exception("update_store_asset_hash_to_asset_value_map() - Lock not locked, Function should only be called from within the lock")
        
        if action == "remove".lower():
            logger.debug(f"update_store_asset_hash_to_asset_value_map() - Removing asset from asset_hash map - asset_hash:{input_asset_hash}")
            if await cls.return_asset_exists_by_hash(input_asset_hash):
                try:
                    del cls.store_asset_hash_to_asset_value_map[input_asset_hash]
                except Exception as e:
                    logger.error(f"update_store_asset_hash_to_asset_value_map({input_asset_hash},{asset}) - Error removing asset from asset_hash map: {e}")
                    return False
                logger.debug(f"update_store_asset_hash_to_asset_value_map() - Removed asset from asset_hash map - asset_hash:{input_asset_hash}")
                return True
            
        logger.debug(f"update_store_asset_hash_to_asset_value_map({input_asset_hash})")        
        try:
            if input_asset_hash not in cls.store_asset_hash_to_asset_value_map.keys():
                cls.store_asset_hash_to_asset_value_map.update({input_asset_hash: asset})
                logger.debug(f"update_store_asset_hash_to_asset_value_map({input_asset_hash})") 
            else:
                logger.error(f"update_store_asset_hash_to_asset_value_map({input_asset_hash},{asset}) - Asset_hash already exists in store_asset_hash_to_asset_value_map")
                return False
        except Exception as e:
            logger.error(
                f"update_store_asset_hash_to_asset_value_map({input_asset_hash},{asset}) - Error adding asset_hash to store_asset_hash_to_asset_value_map: {e}")
            return False
        return True

    @classmethod
    async def update_store_cluster_id_to_asset_hash_list_map(cls, cluster_id: str, input_asset_hash: str,action :str=None) -> bool:
        """Update the cluster_id to asset_hash list map"""
        if not cls._lock.locked():
            raise Exception("update_store_cluster_id_to_asset_hash_list_map() - Lock not locked, Function should only be called from within the lock")
        
        logger.debug(f"update_store_cluster_id_to_asset_hash_list_map({cluster_id},{input_asset_hash})")
        
        if action == "remove":
            try:
                if cluster_id in cls.store_cluster_id_to_asset_hash_list_map.keys():
                    cls.store_cluster_id_to_asset_hash_list_map[cluster_id].remove(input_asset_hash)
                    logger.debug(f"update_store_cluster_id_to_asset_hash_list_map({cluster_id},{input_asset_hash})") 
                else:
                    logger.error(f"update_store_cluster_id_to_asset_hash_list_map({cluster_id},{input_asset_hash}) - Cluster_id does not exist in store_cluster_id_to_asset_hash_list_map")
                    return False
            except Exception as e:
                logger.error(
                    f"update_store_cluster_id_to_asset_hash_list_map({cluster_id},{input_asset_hash}) - Error removing asset_hash from store_cluster_id_to_asset_hash_list_map: {e}")
                return False
            return True
        
        try:
            if cluster_id in cls.store_cluster_id_to_asset_hash_list_map.keys():
                cls.store_cluster_id_to_asset_hash_list_map[cluster_id].append(input_asset_hash)
            else:
                cls.store_cluster_id_to_asset_hash_list_map.update({cluster_id: [input_asset_hash]})
            logger.debug(f"update_store_cluster_id_to_asset_hash_list_map({cluster_id},{input_asset_hash})")
        except Exception as e:
            logger.error(
                f"update_store_cluster_id_to_asset_hash_list_map({cluster_id},{input_asset_hash}) - Error adding asset_hash to store_cluster_id_to_asset_hash_list_map: {e}")
            return False
        return True
      
    @classmethod
    async def return_asset_hash(cls, asset: KDEAsset, cluster_id: str) -> str:
        """Return a hash of the asset and cluster_id"""
        logger.debug(f"return_asset_hash({asset},{cluster_id})")
        return hash(tuple(str(hash(asset))) + tuple(cluster_id))

    @classmethod
    async def return_asset_exists_by_hash(cls, input_asset_hash: str) -> bool:
        """Return a hash of the asset and cluster_id"""
        logger.debug(f"return_asset_exists_by_hash({input_asset_hash})")
        if input_asset_hash in cls.store_asset_hash_to_asset_value_map.keys():
            return True
        return False

    @classmethod
    async def return_kde_exists_by_cluster_id(cls, cluster_id: str) -> bool:
        """Return True if a kde_json exists for a given cluster_id"""
        logger.debug(f"return_kde_exists_by_cluster_id({cluster_id})")
        if cluster_id in cls.store_cluster_id_to_kde_json_output_map.keys():
            return True
        else:
            return False

    @classmethod
    async def return_kde_by_cluster_id(cls, cluster_id: str) -> KDEJsonv2:
        """Return a kde_json by cluster_id"""
        logger.debug(f"return_kde_by_cluster_id({cluster_id})")
        return cls.store_cluster_id_to_kde_json_output_map.get(cluster_id)

    @classmethod
    async def return_asset_alert_id_list(cls, asset_hash: str) -> list[str]:
        """Return a list of AlertIDs for a given asset_id"""
        logger.debug(f"return_asset_alert_id_list({asset_hash})")
        return cls.store_asset_hash_to_alert_id_list_map.get(asset_hash)

    @classmethod
    async def add_new_kde_by_cluster_id(cls, acsalert: ACSAlert, kdeinput: KDEJsonv2):
        """Add a new kde_json by cluster_id because it does not exist"""
        logger.debug(f"add_new_kde_by_cluster_id({acsalert.clusterId})")

        if not await cls.return_kde_exists_by_cluster_id(acsalert.clusterId):
            async with cls._lock:

                # Add the new store_cluster_id_to_kde_json_output_map
                logger.debug(
                    f"add_new_kde_by_cluster_id({acsalert.clusterId}) - got lock")
                
                #Add the new KDEJSONV2
                if await cls.update_store_cluster_id_to_kde_json_output_map(acsalert.clusterId,kdeinput):
                    logger.debug(
                        f"add_new_kde_by_cluster_id({acsalert.clusterId}) - Added new store_cluster_id_to_kde_json_output_map")

                # Update the AlertID Mapping to the list of Assets(Deployments)
                try:
                    for asset in kdeinput.assets:
                        new_hash = await cls.return_asset_hash(asset, acsalert.clusterId)
                        
                        #Update asset_hash to asset_value map
                        await cls.update_store_asset_hash_to_asset_value_map(new_hash, asset)
                        
                        #Update asset_hash to alert_id map
                        await cls.update_store_asset_hash_to_alert_id_list_map(new_hash, acsalert.id)
                        
                        #Update cluster_id to list of asset_hashes in cluster
                        await cls.update_store_cluster_id_to_asset_hash_list_map(acsalert.clusterId, new_hash)
                        
                        #Update alert_id to list of asset_hashes
                        await cls.update_store_alert_id_to_asset_hash_map(acsalert.id, new_hash)
                       
                except Exception as e:
                    logger.error(
                        f"add_new_kde_by_cluster_id({acsalert.clusterId}) - Error adding asset to store_asset_hash_to_alert_id_list_map: {e}")
               
                # Update the AlertID Mapping to the lasttime
                await cls.update_store_alert_id_to_lasttime_map(acsalert.id)

            logger.debug(
                f"add_new_kde_by_cluster_id({acsalert.clusterId}) - released lock")
        else:
            # This means we already have a kde_json for this cluster_id
            logger.error(
                f"add_new_kde_by_cluster_id({acsalert.clusterId}) - kde_json already exists")

    @classmethod
    async def update_existing_asset_by_alert(cls, asset: KDEAsset, acsalert: ACSAlert) ->None:
        """Update an existing asset by asset_hash because it already exists"""
        asset_hash = await cls.return_asset_hash(asset, acsalert.clusterId)
        logger.debug(f"update_existing_asset_by_cluster_id({asset_hash})")
                                
        if await cls.return_asset_exists_by_hash(asset_hash):
            async with cls._lock:
                # Get and update the existing asset
                logger.debug(
                    f"update_existing_asset_by_hash({asset_hash}) - got lock")
                previous_asset = cls.store_asset_hash_to_asset_value_map[asset_hash]

                # Merge the existing asset vulnerabilities with the new ones
                temp_vuln_list = asset.vulns + previous_asset.vulns
                previous_asset.vulns = list(
                    OrderedDict.fromkeys(temp_vuln_list))

                # Merge the existing asset findings with the new ones
                temp_finding_list = asset.findings + previous_asset.findings
                previous_asset.findings = list(
                    OrderedDict.fromkeys(temp_finding_list))

                # Update the AlertID Mapping to the lasttime
                await cls.update_store_alert_id_to_lasttime_map(acsalert.id)
            logger.debug(
                f"update_existing_asset_by_hash({asset_hash}) - released lock")
        else:
            # This means we already have a kde_json for this cluster_id
            logger.error(
                f"update_existing_asset_by_cluster_id({asset_hash}) - asset does not exist will redirect to add_new_asset_by_cluster_id")
            await cls.add_new_asset_by_alert(asset, acsalert)

    @classmethod
    async def add_new_asset_by_alert(cls, asset: KDEAsset, acsalert: ACSAlert):
        """Add a new asset by asset_hash because it does not exist"""
        asset_hash = await cls.return_asset_hash(asset, acsalert.clusterId)
        logger.debug(f"add_new_asset_by_cluster_id({asset_hash})")

        if not await cls.return_asset_exists_by_hash(asset_hash):
            async with cls._lock:
                # Add the new asset to Main KDE ClusterID Asset List
                logger.debug(f"add_new_asset_by_hash({asset_hash}) - got lock")
                await cls.update_store_cluster_id_to_kde_json_output_map(acsalert.clusterId,None,asset)
                
                #Update other asset_hash objects to asset_value map
                await cls.update_store_asset_hash_to_asset_value_map(asset_hash, asset) 
                
                await cls.update_store_cluster_id_to_asset_hash_list_map(acsalert.clusterId,asset_hash)
                
                await cls.update_store_alert_id_to_asset_hash_map(acsalert.id,asset_hash)  
                
                await cls.update_store_asset_hash_to_alert_id_list_map(asset_hash,acsalert.id)             

                logger.debug(
                    f"add_new_asset_by_hash({asset_hash}) - Added new asset")

                # Update the AlertID Mapping to the lasttime
                await cls.update_store_alert_id_to_lasttime_map(acsalert.id)

            logger.debug(
                f"add_new_asset_by_hash({asset_hash}) - released lock")
        else:
            # This means we already have an asset for this asset_hash
            logger.warn(
                f"add_new_asset_by_hash({asset_hash}) - asset already exists will run update_existing_asset_by_alert")
            await cls.update_existing_asset_by_alert(asset, acsalert)

    @classmethod
    async def can_be_overwritten_previous_alert(cls, acsalert:ACSAlert) -> bool:
        logger.debug(
            f"can_be_overwritten_previous_alert - Checking if we need to overwrite {acsalert.id}")
        
        #Check when alert with same alert_id was last seen
        if acsalert.id in cls.store_alert_id_to_lasttime_map.keys():
            # Get the most recent alert from RHACS for this asset
            try:
                most_recent_alert_id = cls.store_alert_id_to_lasttime_map[acsalert.id]
                if int((datetime.now(tz=None)-most_recent_alert_id).total_seconds()) > settings.acs_auto_overwrite_timer:
                    logger.debug(
                        f"can_be_overwritten_previous_alert - Overwrite logic should be applied for alert_id {acsalert.id}")
                    return True
            except ValueError:
                logger.error("can_be_overwritten_previous_alert - Could not apply overwrite logic")
        return False

    @classmethod
    async def remove_previous_alert_information_by_alert(cls, acsalert: ACSAlert):
        """Delete from our information store the previous alert information"""
        logger.debug(f"remove_previous_alert_information {acsalert.id}")
        
        async with cls._lock:
            logger.debug("remove_previous_alert_information - got lock")
            logger.debug("remove_previous_alert_information - Taking a copy of the asset_hashes for alert_id {acsalert.id}")
            temp_asset_hash_list = copy.deepcopy(cls.store_alert_id_to_asset_hash_map[acsalert.id])
            
            for asset_hash in temp_asset_hash_list:
                logger.debug(f"remove_previous_alert_information for {acsalert.id}- Removing asset {asset_hash}")
                asset = cls.store_asset_hash_to_asset_value_map[asset_hash]
                
                ##Remove the asset from Main KDE ClusterID Asset List
                if await cls.update_store_cluster_id_to_kde_json_output_map(acsalert.clusterId,None,asset,"remove"):
                    logger.debug(f"remove_previous_alert_information for {acsalert.id}- Removed asset {asset_hash} from kde_json")     
                                            
                    if await cls.update_store_cluster_id_to_asset_hash_list_map(acsalert.clusterId,asset_hash,"remove"):
                        logger.debug(f"remove_previous_alert_information for {acsalert.id}- Removed asset {asset_hash} from cluster_id_to_asset_hash_list_map")
                    
                    if await cls.update_store_alert_id_to_asset_hash_map(acsalert.id,asset_hash,"remove"):
                        logger.debug(f"remove_previous_alert_information for {acsalert.id}- Removed asset {asset_hash} from alert_id_to_asset_hash_map")

                    if await cls.update_store_asset_hash_to_alert_id_list_map(asset_hash,acsalert.id,"remove"):
                        logger.debug(f"remove_previous_alert_information for {acsalert.id}- Removed asset {asset_hash} from asset_hash_to_alert_id_list_map")

                    if await cls.update_store_asset_hash_to_asset_value_map(asset_hash, asset,"remove"):
                        logger.debug(f"remove_previous_alert_information for {acsalert.id}- Removed asset {asset_hash} from asset_hash_to_asset_value_map")
                                                
        logger.debug("remove_previous_alert_information - released lock")
    
    @classmethod
    async def receive_kdejson(cls, kdeinput: KDEJsonv2, acsalert: ACSAlert) -> None:
        """Add a new KDEJsonv2 Object to the container from outside the class"""
        logger.debug(f"receive_kdejson({acsalert.id})")
        should_we_overwrite_previous_info = False
    
        #If this alert is resolved, we should remove previous alert information and return
        try:
            if acsalert.state is not None:
                if str.lower(acsalert.state) == "resolved":
                    logger.debug("receive_kdejson - Alert is resolved, we should remove previous alert information for alert {}".format(acsalert.id))
                    await cls.remove_previous_alert_information_by_alert(acsalert)
                    return None
        except Exception as e:
            logger.error(f"receive_kdejson - Error checking if we should remove previous alert information {e}")
            
        #Let's Check Reasons why we might need to overwrite previous alert information
        try:
            if settings.acs_auto_overwrite_enabled:
                if await cls.can_be_overwritten_previous_alert(acsalert):
                    logger.debug("receive_kdejson - Overwrite logic should be applied")
                    should_we_overwrite_previous_info = True
        except Exception as e:
            logger.error(f"receive_kdejson - Error checking if we should overwrite previous alert information {e}")
            
        #Check if we our instance is the same as the one that generated the alert i.e App retrieved alert from RHACS
        try:
            if acsalert.acs_instance_ip == instance_hostname:
                logger.debug("receive_kdejson - Alert was generated from this instance, we should overwrite previous alert information")
                should_we_overwrite_previous_info = True
        except Exception as e:
            logger.error(f"receive_kdejson - Error checking if we should overwrite previous alert information {e}")

        #Check if autoclose logic is enabled and if we should autoclase a previous alert with the same alert_id
        if should_we_overwrite_previous_info:              
            #Remove all the assets from the previous alert
            logger.debug("receive_kdejson - Removing previous alert from store for {acsalert.id}")
            await cls.remove_previous_alert_information_by_alert(acsalert)            

        # Check if the cluster_id already exists
        if await cls.return_kde_exists_by_cluster_id(acsalert.clusterId):
            logger.info(
                f"KDEJsonv2 for cluster {acsalert.clusterId} already exists will update")

            # Temp lists to hold the assets we need to add, remove, and update
            temp_input_assets = []
            temp_new_assets = []

            # Parse the assets from the alert
            check_empty_assets = True
            for input_asset in kdeinput.assets:
                check_empty_assets = False
                input_asset_hash = await cls.return_asset_hash(input_asset, acsalert.clusterId)
                if await cls.return_asset_exists_by_hash(input_asset_hash):
                    # This means there is an already existing asset that matches the one we are trying to add
                    logger.debug(f"Found matching asset {input_asset}")
                    temp_input_assets.append(input_asset)
                else:
                    # This means there is no existing asset that matches the one we are trying to add
                    logger.debug(
                        f"Did not find an existing asset for {input_asset} will add it")
                    temp_new_assets.append(input_asset)

            if check_empty_assets:
                # There were no assets we parsed from the alert, really should not happen, our parse might be broken
                logger.warning(
                    f"receive_kdejson({acsalert.id}) - No assets found in kdeinput")

            # Decide how to handle the asset
            # Add new assets
            for input_asset in temp_new_assets:
                logger.debug(
                    f"receive_kdejson({acsalert.id}) - Adding asset {input_asset}")
                await cls.add_new_asset_by_alert(input_asset, acsalert)
                logger.debug(
                    f"receive_kdejson({acsalert.id}) - Adding asset {input_asset}")
                
            # Update existing assets
            for input_asset in temp_input_assets:
                logger.debug(
                    f"receive_kdejson({acsalert.id}) - Updating asset {input_asset}")
                await cls.update_existing_asset_by_alert(input_asset, acsalert)
                logger.debug(
                    f"receive_kdejson({acsalert.id}) - Updated asset {input_asset}")

        # Cluster_id does not exist so add it
        else:
            logger.info(
                f"KDEJsonv2 for cluster {acsalert.clusterId} does not exist will create")
            await cls.add_new_kde_by_cluster_id(acsalert, kdeinput)


# ------------------------------------------------------------------------------------------------


# App Init and Global Variables
# ------------------------------------------------------------------------------------------------
# Logging
log_file_path = path.join(path.dirname(path.abspath(__file__)), 'logging.conf')
config.fileConfig(log_file_path, disable_existing_loggers=False)
logger = getLogger("logger_root")

# Output Folder Directories
kde_output = settings.kde_output_folder
acs_output = settings.acs_output_folder
parent_dir = path.abspath(
    path.join(path.dirname(path.abspath(__file__)), pardir))
full_kde_output = path.join(parent_dir, kde_output)
full_acs_output = path.join(parent_dir, acs_output)

# Other Variables
scanner_type = "redhat_rhacs_scanner"
bulk_count_alerts = 0
count_alerts = 0
continous_kde_loop_task = None
continous_poll_acs_loop_task = None
startup_status = False

# Declare App as a FastApi Object
app = FastAPI()

# Instance Hostname is global
instance_hostname = ""


# ------------------------------------------------------------------------------------------------
# Methods and Routes
# ------------------------------------------------------------------------------------------------


def sync_write_file(fullfilepath, acsalert=None, kdeobject=None, content=None, mode="w+"):
    """ Method to synchonously write to Files"""
    pass

async def path_exists(path: Union[Path, str]) -> bool:
    """Return True if the path exists."""
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

async def async_write_file(fullfilepath, object=None, content=None, mode="w+"):
    """ Method to Asynchonously write Objects to Files,Method Only writes JSON Encodable Objects to Files"""
    count = 1
    tempfullfilepath = fullfilepath
    logger.debug(f"async_write_file({fullfilepath})")

    if object is None and content is None:
        logger.error("async_write_file({fullfilepath}) - No Object or Content to Write")
    if mode != "w" and mode != "w+":
        while await path_exists(f"{tempfullfilepath}.json"):
            tempfullfilepath = '{}_{}'.format(fullfilepath, count)
            count += 1
    if mode == "w" or mode == "w+":
        tempfullfilepath = '{}'.format(fullfilepath)
    filehandle = await async_open(f"{tempfullfilepath}.json", mode=mode)
    logger.debug("async_write_file({fullfilepath}) - Opened File Handle")
    if object is not None:
        await filehandle.write(json.dumps(jsonable_encoder(object), indent=2))
    elif content is not None:
        await filehandle.write(json.dumps(content, indent=2))
    filehandle.close
    logger.debug("async_write_file({fullfilepath}) - Closed File Handle")
    logger.debug(f"async_write_file({fullfilepath}) - Finished")

async def return_scanner_type() -> str:
    """Returns ACS Scanner Type, In future might implement logic to filter ACS Instances"""
    global scanner_type
    return scanner_type

async def acs_alert_message_parser(msg) -> dict:
    """Function to parse ACS Policy Violation Message to Get Vulnerability Information"""
    return_dict = {}
    regex_pal1 = "(^\w+-[0-9\-\:]+)\s\(CVSS\s([0-9\.]+)\)\s\(severity\s(\w+)\)\sfound in component\s\'[\w\-\+\_\*\.]*\'\s\(([\w\s\-\.\_\:\+]*)\)\sin\scontainer\s\'([\w\-]+)\'"
    output = re.findall(regex_pal1, str(msg))
    if output is not None:
        try:
            return_dict.update({"cvss_name": output[0][0]})
            return_dict.update({"cvss_score": output[0][1]})
            return_dict.update({"vuln_severity": output[0][2]})
            return_dict.update({"vuln_affected_image_version": output[0][3]})
            return_dict.update({"vuln_affected_container_name": output[0][4]})
            return return_dict
        except:
            logger.error("Could not correctly parse msg -- {}".format(msg))
    return None

async def initiate_kde_conversion(acsalert: ACSAlert):
    """ Determine then write received info from ACS Alert to KDE File"""
    logger.info("Initiating KDE Conversion for {}".format(acsalert.id))

    # Vuln And Vuldef Storage
    temp_kde_vuln = []
    temp_kde_vuln_def = []
    temp_kde_finding = []

    # Vuln and VulnDev List for Lookback to avoid duplicate
    temp_kde_vuln_name = []
    temp_kde_vuln_def_name = []
    for violation in acsalert.violations:

        output = await acs_alert_message_parser(violation.message)
        if output is None:
            logger.error("Could not correctly parse {}".format(acsalert.id))
            return None

        # With Data From ACS Message Parsing Update our Variables
        try:
            cvss_name = output["cvss_name"]
            cvss_score = output["cvss_score"]
            vuln_severity = output["vuln_severity"]
            vuln_affected_image_version = output["vuln_affected_image_version"]
            vuln_affected_container_name = output["vuln_affected_container_name"]
        except KeyError:
            logger.error(
                "Could not correctly parse ACS Alert -- {}".format(acsalert.id))
            logger.error("Cannot Output KDE for {}".format(acsalert.id))
            return None

        # In case CVSS Score is a float try
        try:
            cvss_score = int(cvss_score)
        except ValueError:
            try:
                cvss_score = float(cvss_score)
                cvss_score = int(cvss_score)
            except:
                logger.error(
                    "Could not convert CVSS Score into Int for KDE - {}".format(acsalert.id))
                return None

        # Add Vuln Definition into KDE,Check if already added
        if cvss_name not in temp_kde_vuln_def_name:
            new_vuln_def = KDEVulnDef(name=cvss_name, scanner_type=await return_scanner_type(), cve_identifiers=cvss_name, description=vuln_severity)
            temp_kde_vuln_def.append(new_vuln_def)
            temp_kde_vuln_def_name.append(cvss_name)
            logger.debug("Added Vuln Def {} to KDE".format(cvss_name))

        if cvss_name not in temp_kde_vuln_name:
            new_vuln = KDEVuln(scanner_identifier=cvss_name, scanner_type=await return_scanner_type(), scanner_score=cvss_score, last_seen_at=acsalert.time, created_at=acsalert.firstOccurred, status="open", vuln_def_name=cvss_name)
            temp_kde_vuln.append(new_vuln)
            temp_kde_vuln_name.append(cvss_name)
            logger.debug("Added Vuln {} to KDE".format(cvss_name))

            new_finding = KDEFinding(scanner_identifier=cvss_name, scanner_type=await return_scanner_type(), scanner_score=cvss_score, last_seen_at=acsalert.time, created_at=acsalert.firstOccurred, vuln_def_name=cvss_name)
            temp_kde_finding.append(new_finding)
            logger.debug("Added Finding {} to KDE".format(cvss_name))

    if settings.aggregation_logic.lower() == "cluster_level":
        # Will attempt to create a KDE Output File Per Cluster
        new_kdeasset = KDEAsset(file=acsalert.clusterName, container_id=acsalert.deployment.id,
                                external_id=acsalert.id, vulns=temp_kde_vuln, findings=temp_kde_finding)
        logger.debug("Created KDE Asset for Deployment {}".format(
            acsalert.deployment.id))

        # Pass Deployment Labels to Asset Tags
        if acsalert.deployment.labels is not None:
            if new_kdeasset.tags is None:
                new_kdeasset.tags = []
            for key in acsalert.deployment.labels:
                new_kdeasset.tags.append("{}:{}".format(
                    key, acsalert.deployment.labels[key]))
            new_kdeasset.tags = list(new_kdeasset.tags)
        logger.debug("Added Deployment Labels to KDE Asset for Deployment {}".format(
            acsalert.deployment.id))

        new_kdejson = KDEJsonv2(assets=list(
            [new_kdeasset]), vuln_defs=temp_kde_vuln_def)
        logger.debug("Created KDE Json for Deployment {}".format(
            acsalert.deployment.id))

        await KDEClusterMemory.receive_kdejson(new_kdejson, acsalert)
        logger.debug("Added KDE Json for Deployment {} to Container".format(
            acsalert.deployment.id))

async def continous_kde_output():
    '''Continuous KDE Output Coroutine'''
    while True:
        logger.info("Starting KDE Output Continous Print Loop")
        for item in KDEClusterMemory.store_cluster_id_to_kde_json_output_map.items():
            logger.debug(
                "Starting KDE Output Continous Print Loop for {}".format(item[0]))
            await async_write_file(f"{full_kde_output}/{item[0]}", object=item[1], content=None, mode="w")
        await AsyncSleep(settings.kde_output_timer)

async def continous_poll_acs_alert_by_alertid():
    '''Continuous Polling of ACS Alerts'''
    
    #Don't run loop if not enabled
    if settings.rox_api_polling_enabled and settings.rox_api_secret is not None:
        #Since we are enabled we will start and continue to run the loop
        logger.info("Starting Continously running ACS Polling Loop - that will connect and poll ACS for Alerts")
        
        while True:
            logger.debug("Running another ACS Alert Polling Loop")
            alert_dict = copy.deepcopy(KDEClusterMemory.store_alert_id_to_lasttime_map)
                
            for alert_id in alert_dict.keys():
                #TODO: Clean up this logic
                logger.debug("Starting ACS Alert Polling Loop for {}".format(alert_id))
                headers={"Authorization": f"Bearer {settings.rox_api_secret}",
                            "Content-Type": "application/json"}
                
                #Set SSL Verification
                if settings.rox_api_url_insecure:
                    verify_ssl = False
                    logger.debug("ACS API SSL Verification is Disabled")
                else:
                    verify_ssl = True
                    logger.debug("ACS API SSL Verification is Enabled")
                
                #Get Alert Information from RHACS
                try:
                    logger.debug("Getting ACS Alert {}".format(alert_id))
                    response_dict = await get_acs_alert(settings.rox_api_url,alert_id,verify_ssl,headers)       
                    if response_dict["error_object"] is not None:
                        logger.error("Failed to get ACS Alert {}- error was {}".format(alert_id,response_dict["error_object"]))
                        continue
                except Exception as e:
                    logger.error("Failed to get ACS Alert {}- exception was {}".format(alert_id,e))
                    continue

                #Load Alert Information into JSON 
                try:
                    jsonacsalert = json.loads(response_dict["response_object"].text)
                    if "error" in jsonacsalert.keys():
                        #If RHACS does not know about this alert we will remove it from our memory
                        logger.error("RHACS does not seem to be aware of this alert,we will remove it from our memory")
                        acsalert=ACSAlert.parse_obj(jsonacsalert)
                        await KDEClusterMemory.remove_previous_alert_information_by_alert(acsalert)
                except Exception as e:
                    logger.error("Failed to parse ACS Alert {} - exception was {}".format(alert_id,e))
                    continue
                
                #Parse JSON into Pydantic Model and feed into determine_metadata start loop
                try:                 
                    acsalert=ACSAlert.parse_obj(jsonacsalert)
                    acsalert.acs_instance_ip = instance_hostname
                    await initiate_kde_conversion(acsalert)
                except Exception as e:
                    logger.error("Failed to parse ACS Alert {} - exception was {}".format(alert_id,e))
                    continue      
                
                await AsyncSleep(settings.rox_api_polling_spacer_timer)
                logger.debug("Finished ACS Alert Polling for {}".format(alert_id))
            logger.info("Finished ACS Alert Polling Loop,")

            await AsyncSleep(settings.rox_api_polling_timer)
        
# Get Startup Information
@app.on_event("startup")
async def startup_event():
    '''Startup Function'''
    logger.info("Starting up ACS/Kenna Integration Service")
    global instance_hostname  # pylint: disable=global-statement
    global continous_kde_loop_task  # pylint: disable=global-statement
    global continous_poll_acs_loop_task # pylint: disable=global-statement
    global startup_status  # pylint: disable=global-statement

    instance_hostname = getenv('HOSTNAME')
    logger.info("Instance Hostname: {}".format(instance_hostname))

    # Checking KDE Output Directory Exists
    if not await path_exists(full_kde_output):
        logger.error(
            f"KDE Output Directory - {full_kde_output} does not exist, will attempt creating it")
        try:
            mkdir(full_kde_output)
        except:
            logger.error(
                f"KDE Output Directory - {full_kde_output} could not be created, please create it manually")
            exit(1)
    logger.debug(f"KDE Output Directory - {full_kde_output} exists")

    # Checking ACS Output Directory Exists
    if not await path_exists(full_acs_output):
        logger.error(
            f"ACS Example Output Directory - {full_acs_output} does not exist, will attempt creating it")
        try:
            mkdir(full_acs_output)
        except:
            logger.error(
                f"ACS Example Output Directory - {full_acs_output} could not be created, please create it manually")
            exit(1)
    logger.debug(f"ACS Example Output Directory - {full_acs_output} exists")
    
    #Checking if we can poll ACS
    if settings.rox_api_polling_enabled and not settings.rox_api_secret is None:
        logger.info("Polling ACS API for Alerts is Enabled,will attempt to connect to ACS API")
        headers={"Authorization": f"Bearer {settings.rox_api_secret}",
                 "Content-Type": "application/json"}
        
        if settings.rox_api_url_insecure:
            verify_ssl = False
            logger.debug("ACS API SSL Verification is Disabled")
        else:
            verify_ssl = True
            logger.debug("ACS API SSL Verification is Enabled")
        
        try:
            response_dict = await get_rhacs_health(settings.rox_api_url,verify_ssl,headers)
            if response_dict["response_object"].status_code == 200:
                logger.info("ACS API Connection Successful")
                if settings.storage_type.lower() == "memory":
                    logger.info("Since we can poll ACS API, we will start an ACS API Polling Loop for Alerts in Memory")
                    continous_poll_acs_loop_task = create_task(continous_poll_acs_alert_by_alertid())
            else:
                logger.error("ACS API Connection Failed, will continue without ACS API Polling")
                settings.rox_api_polling_enabled = False 
        except Exception as e:
            logger.error("ACS API Connection Failed, will continue without ACS API Polling - exception was {}")
            settings.rox_api_polling_enabled = False
            
    #Start Continous KDE Output
    logger.debug("Starting Continous KDE Output Loop which will update the KDE Output Directory every {} seconds".format(settings.kde_output_timer))
    continous_kde_loop_task = create_task(continous_kde_output())
    logger.info("Continous KDE Output Loop Started")
    
    #Startup Complete
    startup_status = True
    logger.info("Startup Complete")

@app.get("/")
async def root():
    '''Application'''
    logger.info("Root Url '/' was Called")
    return {"Application": "Integration Service for Red Hat Advanced Cluster Security Service with Kenna Security"}

@app.get("/health")
async def health():
    '''Application Health URL'''
    logger.debug("Health Url '/health' was Called")
    return {"status": "OK"}

@app.get("/ready")
async def ready():
    '''Application Readiness URL'''
    global startup_status  # pylint: disable=global-statement
    
    logger.debug("Health Url '/ready' was Called")
    if startup_status:
        logger.debug("Application is Ready")
        return {"status": "OK"}
    else:
        logger.debug("Application is Not Ready")
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"status": "Not Ready"})

@app.post("/load_bulk_acs_alerts")
async def determine_metadata_bulk(request: Request):
    """Function not meant for normal use, used to load bulk alerts into the system for testing purposes"""
    global bulk_count_alerts  # pylint: disable=global-statement
    global full_acs_output  # pylint: disable=global-statement

    bulk_count_alerts += 1
    json_temp = await request.json()
    json_formatted_str = json.dumps(json_temp, indent=2)
    logger.info("{}".format(json.dumps(json_temp, indent=2)))
    await async_write_file(f"{full_acs_output}/acs_alert_example", None, json_temp, "a")
    return {"status": "OK"}


@app.post("/receive_acs_vuln_alert")
async def determine_metadata(background_tasks: BackgroundTasks, response: Response, request: Request, return_flag: str = None, alert: ACSAlert = Body(embed=True)):
    logger.info("Recieved Alert with ID: {}".format(alert.id))
    global count_alerts  # pylint: disable=global-statement
    
    try:
        alert.acs_instance_ip = request.client.host
    except AttributeError as error:
        if "object has no attribute 'client'" in error.args[0]:
            logger.debug("This means the request was made from the same server")
            alert.acs_instance_ip = instance_hostname
        else:
            logger.error("Unable to get IP Address of ACS Instance")
            alert.acs_instance_ip = "Unknown"
    logger.info("Alert with ID: {} was received from IP: {}".format(
        alert.id, alert.acs_instance_ip))
    count_alerts += 1

    if return_flag is not None:
        await initiate_kde_conversion(alert)
        if return_flag == "message":
            logger.debug(
                "Returning Message for Alert with ID: {}".format(alert.id))

            return alert.json(include={'violations'})
        if return_flag == "all":
            logger.debug(
                "Returning Alert for Alert with ID: {}".format(alert.id))
            return alert.json()
    else:
        logger.debug(
            "Adding Alert with ID: {} to Background Tasks".format(alert.id))
        background_tasks.add_task(initiate_kde_conversion, alert)
        logger.debug(
            "Added Alert with ID: {} to Background Tasks".format(alert.id))
        return {"status": "Recieved Alert with ID: {}".format(alert.id)}


@app.get("/obtain_kde_output_files")
async def obtain_kde_files(kdealert: KDEJsonv2 = None):
    return None
