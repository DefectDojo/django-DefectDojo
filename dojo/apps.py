from django.apps import AppConfig
from watson import search as watson
from django.db import models


import logging
logger = logging.getLogger(__name__)


class DojoAppConfig(AppConfig):
    name = 'dojo'
    verbose_name = "Defect Dojo"

    def ready(self):
        # we need to initializer waston here because in models.py is to early if we want add extra fields to index
        print('ready(): initializing watson')
        # logger doesn't work yet at this stage

        # Watson doesn't have a way to let it index extra fields, so we have to explicitly list all the fields
        # to make it easier, we get the charfields/textfields from the model and then add our extra fields.
        # charfields/textfields are the fields that watson indexes by default (but we have to repeat here if we add extra fields)
        # and watson likes to have tuples instead of lists

        watson.register(self.get_model('Product'), fields=get_model_fields_with_extra(self.get_model('Product'), ('prod_type__name', )), store=('prod_type__name', ))

        watson.register(self.get_model('Test'), fields=get_model_fields_with_extra(self.get_model('Test'), ('engagement__product__name', )), store=('engagement__product__name', ))  # test_type__name?

        watson.register(self.get_model('Finding'), fields=get_model_fields_with_extra(self.get_model('Finding'), ('test__engagement__product__name', 'jira_issue__jira_key', )),
                        store=('cve', 'status', 'jira_issue__jira_key', 'test__engagement__product__name', 'severity', 'severity_display', 'latest_note'))

        # some thoughts on Finding fields that are not indexed yet:
        # CWE can't be indexed as it is an integer

        # would endpoints be good to index? or would it clutter search results?
        # endpoints = models.ManyToManyField(Endpoint, blank=True)
        # endpoint_status = models.ManyToManyField(Endpoint_Status, blank=True, related_name='finding_endpoint_status')

        # index test name/title?
        # test = models.ForeignKey(Test, editable=False, on_delete=models.CASCADE)

        # index reporter name?
        # reporter = models.ForeignKey(User, editable=False, default=1, related_name='reporter', on_delete=models.CASCADE)
        # index notes?
        # notes = models.ManyToManyField(Notes, blank=True, editable=False)

        # index found_by?
        # found_by = models.ManyToManyField(Test_Type, editable=False)

        # exclude these to avoid cluttering?
        # sast_source_object = models.CharField(null=True, blank=True, max_length=500, help_text="Source object (variable, function...) of the attack vector")
        # sast_sink_object = models.CharField(null=True, blank=True, max_length=500, help_text="Sink object (variable, function...) of the attack vector")
        # sast_source_line = models.IntegerField(null=True, blank=True,
        #                            verbose_name="Line number",
        #                            help_text="Source line number of the attack vector")
        # sast_source_file_path = models.CharField(null=True, blank=True, max_length=4000, help_text="Source filepath of the attack vector")

        watson.register(self.get_model('Finding_Template'))
        watson.register(self.get_model('Endpoint'), store=('product__name', ))  # add product name also?
        watson.register(self.get_model('Engagement'), fields=get_model_fields_with_extra(self.get_model('Engagement'), ('product__name', )), store=('product__name', ))
        watson.register(self.get_model('App_Analysis'))

        # YourModel = self.get_model("YourModel")
        # watson.register(YourModel)

        print('setting up tracing/trace')
        # sys.settrace(trace)
        sys.settrace(trace_calls)        


def get_model_fields_with_extra(model, extra_fields=()):
    return get_model_fields(get_model_default_fields(model), extra_fields)


def get_model_fields(default_fields, extra_fields=()):
    combined = default_fields + extra_fields
    # print(combined)
    return combined


def get_model_default_fields(model):
    return tuple(
        field.name for field in model._meta.fields if
        isinstance(field, (models.CharField, models.TextField))
    )


def trace(frame, event, arg):
    if event == "call":
        filename = frame.f_code.co_filename
        if "dojo" in filename:
            lineno = frame.f_lineno
            # Here I'm printing the file and line number, 
            # but you can examine the frame, locals, etc too.
            print("trace: %s @ %s" % (filename, lineno))
    return trace

def trace_lines(frame, event, arg):
    if event != 'line':
        return
    co = frame.f_code
    func_name = co.co_name
    line_no = frame.f_lineno
    filename = co.co_filename
    print( '  %s line %s' % (func_name, line_no))

def trace_calls(frame, event, arg):
    if event != 'call':
        return
    filename = frame.f_code.co_filename
    if "dojo" in filename:
        co = frame.f_code
        func_name = co.co_name
        if func_name == 'write':
            # Ignore write() calls from print statements
            return
        line_no = frame.f_lineno
        filename = co.co_filename
        print('Call to %s on line %s of %s' % (func_name, line_no, filename))
        # if func_name in TRACE_INTO:
        #     # Trace into this function
        #     return trace_lines
    return
