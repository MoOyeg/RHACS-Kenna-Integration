from httpx import AsyncClient,HTTPError,RequestError,TimeoutException,ConnectTimeout
import os
from httpx._config import SSLConfig
from logging import getLogger, config


import logging
try:
    logger = getLogger("logger_root")
except:
    logger = logging.getLogger(__name__)

async def request_processing(full_url_path,insecure:bool=False,headers:dict=None) -> dict:
    """Send the Request and process the response"""
    logger.debug(f"request_processing -start: url:{full_url_path} verify_ssl:{insecure}")
    error=None
    
    try:
        async with AsyncClient(verify=insecure) as client:        
            response = await client.get(
                f"{full_url_path}",headers=headers            
            )
            logger.debug(f"request_processing - attempted request")
            response.raise_for_status()
    except ConnectTimeout as timeout_err:
        logger.error(f" Connect Timeout error occurred: {timeout_err}")
        error=f"Connect Timeout error occurred: {timeout_err}"
    except TimeoutException as timeout_err:
        logger.error(f"Timeout error occurred: {timeout_err}")
        error=f"Timeout error occurred: {timeout_err}"
    except RequestError as req_err:
        logger.error(f"Error occurred while processing request: {req_err}")
        error=f"Error occurred while processing request: {req_err}"
    except HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err}")
        error=f"HTTP error occurred: {http_err}"
    except Exception as e:
        logger.error(f"Other error occurred: {e}")
        error=f"Other error occurred: {e}"
                
    return {"response_object":response,"error_object":error} 

async def get_acs_alert(url,alert_id: str,insecure:bool=False,headers:dict=None) -> dict:
    """Get ACS alert from the API"""
    logger.debug(f"get_acs_alert -start: url:{url} id:{alert_id} verify_ssl:{insecure}")
    rhacs_alert_url_path=f"{url}/v1/alerts/{alert_id}"
    response_dict = await request_processing(rhacs_alert_url_path,insecure,headers)
    logger.debug(f"get_acs_alert - complete")
    return response_dict
    

async def get_rhacs_health(url,insecure:bool=False,headers:dict=None) -> dict:
    """Get health from the API"""
    logger.debug(f"get_rhacs_health -start: url:{url}")
    rhacs_health_url_path=f"{url}/v1/ping"
    response_dict = await request_processing(rhacs_health_url_path,insecure,headers)
    logger.debug(f"get_rhacs_health - complete")
    return response_dict