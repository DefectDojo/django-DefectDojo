import json
import os
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from dojo.celery import app
from dojo.decorators import dojo_async_task
from dojo.problem.helper import CONFIG_FILE, validate_json, download_json, save_json_to_cache

import logging
logger = logging.getLogger(__name__)


@dojo_async_task
@app.task
def daily_cache_update(**kwargs):
    logger.info("Starting daily cache update")
    try:
        # Disable SSL warnings
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                json_url = config.get('json_url')
                if json_url:
                    data = download_json(json_url)
                    if validate_json(data):
                        save_json_to_cache(data)
                    else:
                        logger.error('Disambiguator JSON is invalid')
                else:
                    logger.error('No JSON URL found in config')
        else:
            logger.error('Config file not found')
    except (requests.RequestException, ValueError, json.JSONDecodeError) as e:
        logger.error('Error updating cache: %s', e)
