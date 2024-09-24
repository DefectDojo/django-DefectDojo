from django.db import models
from django.utils.translation import gettext as _


class FindingExclusion(models.Model):

    TYPE_CHOICES = [("white_list", "white_list"),
                    ("black_list", "black_list")]
    STATUS_CHOICES = [("Accepted", "Accepted"),
                      ("Pending", "Pending"),
                      ("Rejected", "Rejected")]
    type = models.CharField(max_length=12, choices=TYPE_CHOICES)
    unique_id_from_tool = models.CharField(
        blank=True,
        max_length=500,
        verbose_name=_("Unique ID from tool"),
        help_text=_("Vulnerability technical id from the source tool. Allows to track unique vulnerabilities."))

    create_date = models.DateTimeField(auto_now=True)
    expiration_date = models.DateTimeField()
    user_history = models.IntegerField(null=True)
    product = models.ForeignKey("Product",
                                null=True,
                                blank=True,
                                on_delete=models.CASCADE)
    finding = models.ForeignKey("Finding",
                                null=True,
                                blank=True,
                                on_delete=models.CASCADE)
    reason = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=8, choices=STATUS_CHOICES, blank=True, default="Pending")
    accepted_by = models.ForeignKey("Dojo_User",
                                    null=True,
                                    blank=True,
                                    on_delete=models.CASCADE)
    
    class Meta:
        db_table = "dojo_finding_exlusion"
