from pydantic import BaseSettings
import os
from dotenv import load_dotenv  # pylint: disable=import-error


basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Settings(BaseSettings):
    """Application Settings """
    #Presently aggregate output at cluster level - TODO Support aggregation at namespace level
    aggregation_logic:str = os.environ.get('AGGREGATION_LOGIC') or 'cluster_level'
    
    #Presently only supporting memory storage - TODO Use Mongo for Storage and Syncing
    storage_type:str = os.environ.get('STORAGE_TYPE') or 'memory'
    
    #Output Folder Directories
    acs_output_folder:str = os.environ.get('ACS_OUTPUT_FOLDER') or 'acs_example_json'
    kde_output_folder:str = os.environ.get('KDE_OUTPUT_FOLDER') or 'kde_output_json'
    
    #Secret to connect to RHACS API and pull updated information on vulnerabilities
    rox_api_polling_enabled:bool = os.environ.get('ROX_API_POLLING_ENABLED') or True
    rox_api_secret:str = os.environ.get('ROX_API_SECRET') or ""
    rox_api_url:str = os.environ.get('ROX_API_URL') or ""
    rox_api_url_insecure:bool = os.environ.get('ROX_API_URL_INSECURE') or True
    #This timer is used to determine how often we should poll the API for updated information on vulnerabilities i.e if set to 3600, we will poll the API every hour for updated information
    rox_api_polling_timer:int = os.environ.get('ROX_API_POLLING_TIMER') or 60
    #This timer exists to avoid hitting the API too frequently. This is a timer to wait between each API call.
    rox_api_polling_spacer_timer = os.environ.get('ROX_API_POLLING_SPACER_TIMER') or 5
    
    #Output Generation Timer in seconds. If we want to generate output every 5 minutes, set this to 300.
    #This is required since the file system is not a real time database and we dont want to generate output file every time a new vulnerability is found.
    kde_output_timer:int = os.environ.get('KDE_OUTPUT_TIMER') or 300
    
    #auto_overwrite logic - RHACS can send an information in more than 1 alert.
    #By default, we will merge vulnerability information for all alerts on each asset(deployment)
    #If enabled - we will overwrite the vulnerability information for each asset(deployment) with the latest alert information
    acs_auto_overwrite_enabled:bool = os.environ.get('ACS_AUTOCLOSE_ENABLED') or False
    acs_auto_overwrite_timer:int = os.environ.get('ACS_AUTO_OVERWRITE_TIMER') or 60  

    #TODO - Use Mongo for Storage and Syncing
    #monogodb_uri = os.environ.get('MONGODB_URI') or 'mongodb://localhost:27017'


settings = Settings()
