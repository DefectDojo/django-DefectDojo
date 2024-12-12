from django.db import models
from django.contrib import admin
from django.utils.translation import gettext as _

import uuid


class FindingExclusion(models.Model):
    TYPE_CHOICES = [("white_list", "white_list"),
                    ("black_list", "black_list")]
    STATUS_CHOICES = [("Accepted", "Accepted"),
                      ("Pending", "Pending"),
                      ("Reviewed", "Reviewed"),
                      ("Rejected", "Rejected")]
    uuid = models.UUIDField(default=uuid.uuid4, primary_key=True)
    type = models.CharField(max_length=12, choices=TYPE_CHOICES)
    unique_id_from_tool = models.CharField(
        blank=True,
        max_length=500,
        verbose_name=_("Unique ID from tool"),
        help_text=_("Vulnerability technical id from the source tool. Allows to track unique vulnerabilities."))

    create_date = models.DateTimeField(auto_now_add=True)
    expiration_date = models.DateTimeField(null=True)
    last_status_update = models.DateTimeField(auto_now=True)
    status_updated_at = models.DateTimeField(null=True)
    status_updated_by = models.ForeignKey("Dojo_User",
                                          null=True,
                                          related_name="dojo_user_status_updated",
                                          on_delete=models.CASCADE)
    reviewed_at = models.DateTimeField(null=True, blank=True)
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
    final_status = models.CharField(choices=[("Accepted", "Accepted"), ("Rejected", "Rejected")], null=True)
    accepted_by = models.ForeignKey("Dojo_User",
                                    null=True,
                                    blank=True,
                                    on_delete=models.CASCADE)
    created_by = models.ForeignKey("Dojo_User",
                                   null=True,
                                   blank=True,
                                   on_delete=models.CASCADE,
                                   related_name="dojo_user_created")
    
    class Meta:
        db_table = "dojo_finding_exlusion"


class FindingExclusionDiscussion(models.Model):
    finding_exclusion = models.ForeignKey("FindingExclusion", on_delete=models.CASCADE, related_name='discussions')
    author = models.ForeignKey("Dojo_User", on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Discussion by {self.author.username} on {self.created_at}"
    
    class Meta:
        db_table = "dojo_finding_exclusion_discussion"
        

admin.site.register(FindingExclusion)
admin.site.register(FindingExclusionDiscussion)
