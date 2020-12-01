from dojo.cb_utils import auto_delete_engagements
# from dojo.models import System_Settings
from dojo.celery import app
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@app.task(name='dojo.cb_tasks.auto_delete_engagements')
def async_auto_delete_engagements(*args, **kwargs):
    try:
        # system_settings = System_Settings.objects.get()
        # if system_settings.engagement_auto_delete_enable:
        logger.info("Automatically deleting engagements and related as needed")
        auto_delete_engagements(*args, **kwargs)
    except Exception as e:
        logger.error("An unexpected error was thrown calling the engagements auto deletion code: {}".format(e))
