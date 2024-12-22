import json
import os
import requests

from dojo.celery import app
from dojo.decorators import dojo_async_task
from dojo.problem.helper import load_json

import logging
logger = logging.getLogger(__name__)


@dojo_async_task
@app.task
def daily_cache_update(**kwargs):
    logger.info("Starting daily cache update")
    load_json(check_cash=False)
