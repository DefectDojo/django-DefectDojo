from functools import wraps
import logging


logger = logging.getLogger(__name__)


# Defect Dojo performs all tasks asynchrnonously using celery
# *unless* the user initiating the task has set block_execution to True in their usercontactinfo profile
def dojo_async_task(func):
    @wraps(func)
    def __wrapper__(*args, **kwargs):
        from dojo.utils import get_current_user
        user = get_current_user()
        from dojo.models import Dojo_User
        if Dojo_User.wants_block_execution(user):
            logger.debug('dojo_async_task: running task in the foreground as block_execution is set to True for %s', user)
            return func(*args, **kwargs)
        else:
            return func.delay(*args, **kwargs)
    return __wrapper__
