from django.db import models


# product_opts = [f.name for f in Product._meta.fields]
# test_opts = [f.name for f in Test._meta.fields]
# test_type_opts = [f.name for f in Test_Type._meta.fields]
finding_opts = [f.name for f in Finding._meta.fields if f.name not in ['last_status_update']]
# endpoint_opts = [f.name for f in Endpoint._meta.fields]
# engagement_opts = [f.name for f in Engagement._meta.fields]
# product_type_opts = [f.name for f in Product_Type._meta.fields]
# single_options = product_opts + test_opts + test_type_opts + finding_opts + \
#                  endpoint_opts + engagement_opts + product_type_opts
all_options = []
for x in finding_opts:
    all_options.append((x, x))
operator_options = (('Matches', 'Matches'),
                    ('Contains', 'Contains'))
application_options = (('Append', 'Append'),
                      ('Replace', 'Replace'))
blank_options = (('', ''),)


class Rule(models.Model):
    # add UI notification to let people know what rules were applied

    name = models.CharField(max_length=200)
    enabled = models.BooleanField(default=True)
    text = models.TextField()
    operator = models.CharField(max_length=30, choices=operator_options)
    """
    model_object_options = (('Product', 'Product'),
                            ('Engagement', 'Engagement'), ('Test', 'Test'),
                            ('Finding', 'Finding'), ('Endpoint', 'Endpoint'),
                            ('Product Type', 'Product_Type'), ('Test Type', 'Test_Type'))
    """
    model_object_options = (('Finding', 'Finding'),)
    model_object = models.CharField(max_length=30, choices=model_object_options)
    match_field = models.CharField(max_length=200, choices=all_options)
    match_text = models.TextField()
    application = models.CharField(max_length=200, choices=application_options)
    applies_to = models.CharField(max_length=30, choices=model_object_options)
    # TODO: Add or ?
    # and_rules = models.ManyToManyField('self')
    applied_field = models.CharField(max_length=200, choices=(all_options))
    child_rules = models.ManyToManyField('self', editable=False)
    parent_rule = models.ForeignKey('self', editable=False, null=True, on_delete=models.CASCADE)


class Child_Rule(models.Model):
    # add UI notification to let people know what rules were applied
    operator = models.CharField(max_length=30, choices=operator_options)
    """
    model_object_options = (('Product', 'Product'),
                            ('Engagement', 'Engagement'), ('Test', 'Test'),
                            ('Finding', 'Finding'), ('Endpoint', 'Endpoint'),
                            ('Product Type', 'Product_Type'), ('Test Type', 'Test_Type'))
    """
    model_object_options = (('Finding', 'Finding'),)
    model_object = models.CharField(max_length=30, choices=model_object_options)
    match_field = models.CharField(max_length=200, choices=all_options)
    match_text = models.TextField()
    # TODO: Add or ?
    # and_rules = models.ManyToManyField('self')
    parent_rule = models.ForeignKey(Rule, editable=False, null=True, on_delete=models.CASCADE)


class FieldRule(models.Model):
    field = models.CharField(max_length=200)
    update_options = (('Append', 'Append'),
                        ('Replace', 'Replace'))
    update_type = models.CharField(max_length=30, choices=update_options)
    text = models.CharField(max_length=200)
