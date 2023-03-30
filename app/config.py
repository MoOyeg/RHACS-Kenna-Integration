from pydantic import BaseSettings
import os
from dotenv import load_dotenv  # pylint: disable=import-error


basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))


class Settings(BaseSettings):
    aggregation_logic = os.environ.get('AGGREGATION_LOGIC') or 'cluster_level'
    storage_type = os.environ.get('STORAGE_TYPE') or 'memory'
    #monogodb_uri = os.environ.get('MONGODB_URI') or 'mongodb://localhost:27017'


settings = Settings()