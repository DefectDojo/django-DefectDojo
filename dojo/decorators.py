from functools import wraps
from dojo.models import Finding
from django.db import models
from django.conf import settings
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


# decorator with parameters needs another wrapper layer
# example usage: @dojo_model_to_id(parameter=0) but defaults to parameter=0
def dojo_model_to_id(_func=None, *, parameter=0):
    # logger.debug('dec_args:' + str(dec_args))
    # logger.debug('dec_kwargs:' + str(dec_kwargs))
    # logger.debug('_func:%s', _func)

    def dojo_model_from_id_internal(func, *args, **kwargs):
        @wraps(func)
        def __wrapper__(*args, **kwargs):
            if not settings.CELERY_PASS_MODEL_BY_ID:
                return func(*args, **kwargs)

            model_or_id = get_parameter_froms_args_kwargs(args, kwargs, parameter)

            if model_or_id:
                if isinstance(model_or_id, models.Model):
                    logger.debug('converting model_or_id to id: %s', model_or_id)
                    id = model_or_id.id
                    args = list(args)
                    args[parameter] = id

            return func(*args, **kwargs)

        return __wrapper__

    if _func is None:
        # decorator called without parameters
        return dojo_model_from_id_internal
    else:
        return dojo_model_from_id_internal(_func)


# decorator with parameters needs another wrapper layer
# example usage: @dojo_model_from_id(parameter=0, model=Finding) but defaults to parameter 0 and model Finding
def dojo_model_from_id(_func=None, *, model=Finding, parameter=0):
    # logger.debug('dec_args:' + str(dec_args))
    # logger.debug('dec_kwargs:' + str(dec_kwargs))
    # logger.debug('_func:%s', _func)
    # logger.debug('model: %s', model)

    def dojo_model_from_id_internal(func, *args, **kwargs):
        @wraps(func)
        def __wrapper__(*args, **kwargs):
            if not settings.CELERY_PASS_MODEL_BY_ID:
                return func(*args, **kwargs)

            logger.debug('args:' + str(args))
            logger.debug('kwargs:' + str(kwargs))

            logger.debug('checking if we need to convert id to model: %s for parameter: %s', model.__name__, parameter)

            model_or_id = get_parameter_froms_args_kwargs(args, kwargs, parameter)

            if model_or_id:
                if not isinstance(model_or_id, models.Model):
                    logger.debug('instantiating model_or_id: %s for model: %s', model_or_id, model)
                    try:
                        instance = model.objects.get(id=model_or_id)
                    except model.DoesNotExist:
                        logger.debug('error instantiating model_or_id: %s for model: %s: DoesNotExist', model_or_id, model)
                        instance = None
                    args = list(args)
                    args[parameter] = instance
                else:
                    logger.debug('model_or_id already a model instance %s for model: %s', model_or_id, model)

            return func(*args, **kwargs)

        return __wrapper__

    if _func is None:
        # decorator called without parameters
        return dojo_model_from_id_internal
    else:
        return dojo_model_from_id_internal(_func)


def get_parameter_froms_args_kwargs(args, kwargs, parameter):
    model_or_id = None
    if isinstance(parameter, int):
        # Lookup value came as a positional argument
        args = list(args)
        if parameter >= len(args):
            raise ValueError('parameter index invalid: ' + str(parameter))
        model_or_id = args[parameter]
    else:
        # Lookup value was passed as keyword argument
        model_or_id = kwargs.get(parameter, None)

    logger.debug('model_or_id: %s', model_or_id)

    if not model_or_id:
        logger.error('unable to get parameter: ' + parameter)

    return model_or_id
