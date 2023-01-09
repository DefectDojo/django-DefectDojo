from django.db import models
from django.utils.translation import gettext as _


class Benchmark_Type(models.Model):
    name = models.CharField(max_length=300)
    version = models.CharField(max_length=15)
    source = (('PCI', 'PCI'),
              ('OWASP ASVS', 'OWASP ASVS'),
              ('OWASP Mobile ASVS', 'OWASP Mobile ASVS'))
    benchmark_source = models.CharField(max_length=20, blank=False,
                                        null=True, choices=source,
                                        default='OWASP ASVS')
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return self.name + " " + self.version


class Benchmark_Category(models.Model):
    type = models.ForeignKey(Benchmark_Type, verbose_name=_('Benchmark Type'), on_delete=models.CASCADE)
    name = models.CharField(max_length=300)
    objective = models.TextField()
    references = models.TextField(blank=True, null=True)
    enabled = models.BooleanField(default=True)
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('name',)

    def __str__(self):
        return self.name + ': ' + self.type.name


class Benchmark_Requirement(models.Model):
    category = models.ForeignKey(Benchmark_Category, on_delete=models.CASCADE)
    objective_number = models.CharField(max_length=15, null=True, blank=True)
    objective = models.TextField()
    references = models.TextField(blank=True, null=True)
    level_1 = models.BooleanField(default=False)
    level_2 = models.BooleanField(default=False)
    level_3 = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)
    cwe_mapping = models.ManyToManyField('CWE', blank=True)
    testing_guide = models.ManyToManyField('Testing_Guide', blank=True)
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.objective_number) + ': ' + self.category.name


class Benchmark_Product(models.Model):
    product = models.ForeignKey('Product', on_delete=models.CASCADE)
    control = models.ForeignKey(Benchmark_Requirement, on_delete=models.CASCADE)
    pass_fail = models.BooleanField(default=False, verbose_name=_('Pass'),
                                    help_text=_('Does the product meet the requirement?'))
    enabled = models.BooleanField(default=True,
                                  help_text=_('Applicable for this specific product.'))
    notes = models.ManyToManyField('Notes', blank=True, editable=False)
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.product.name + ': ' + self.control.objective_number + ': ' + self.control.category.name

    class Meta:
        unique_together = [('product', 'control')]


class Benchmark_Product_Summary(models.Model):
    product = models.ForeignKey('Product', on_delete=models.CASCADE)
    benchmark_type = models.ForeignKey(Benchmark_Type, on_delete=models.CASCADE)
    asvs_level = (('Level 1', 'Level 1'),
                    ('Level 2', 'Level 2'),
                    ('Level 3', 'Level 3'))
    desired_level = models.CharField(max_length=15,
                                     null=False, choices=asvs_level,
                                     default='Level 1')
    current_level = models.CharField(max_length=15, blank=True,
                                     null=True, choices=asvs_level,
                                     default='None')
    asvs_level_1_benchmark = models.IntegerField(null=False, default=0, help_text=_("Total number of active benchmarks for this application."))
    asvs_level_1_score = models.IntegerField(null=False, default=0, help_text=_("ASVS Level 1 Score"))
    asvs_level_2_benchmark = models.IntegerField(null=False, default=0, help_text=_("Total number of active benchmarks for this application."))
    asvs_level_2_score = models.IntegerField(null=False, default=0, help_text=_("ASVS Level 2 Score"))
    asvs_level_3_benchmark = models.IntegerField(null=False, default=0, help_text=_("Total number of active benchmarks for this application."))
    asvs_level_3_score = models.IntegerField(null=False, default=0, help_text=_("ASVS Level 3 Score"))
    publish = models.BooleanField(default=False, help_text=_('Publish score to Product.'))
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.product.name + ': ' + self.benchmark_type.name

    class Meta:
        unique_together = [('product', 'benchmark_type')]
