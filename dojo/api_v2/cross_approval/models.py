from django.db import models


class CrossApprovalRequest(models.Model):
    STATUS_CHOICES = (
        ("pending", "Pending"),
        ("approved", "Approved"),
        ("rejected", "Rejected"),
        ("deleting", "Deleting"),
    )

    owner = models.CharField(max_length=50, default="x86")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        "Dojo_User", on_delete=models.PROTECT, related_name="crossapproval_requests_created"
    )
    status_updated_by = models.ForeignKey(
        "Dojo_User", null=True, blank=True, on_delete=models.PROTECT,
        related_name="crossapproval_requests_status_updated",
    )
    status_updated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)
        verbose_name = "Cross-approval request"
        verbose_name_plural = "Cross-approval requests"

    def __str__(self):
        return f"Cross-approval request {self.pk}"


class CrossApprovalExclusion(models.Model):
    request = models.ForeignKey(
        CrossApprovalRequest, on_delete=models.CASCADE, related_name="exclusions"
    )
    vulnerability_id = models.CharField(max_length=255)
    where = models.CharField(max_length=255)
    create_date = models.DateField()
    expired_date = models.DateField()
    priority = models.CharField(max_length=50, blank=True)
    severity = models.CharField(max_length=50, blank=True)
    hu = models.CharField(max_length=100)
    reason = models.TextField()
    component_type = models.CharField(max_length=50, default="image")
    component_values = models.JSONField(default=list)
    expired_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("id",)

    def __str__(self):
        return self.vulnerability_id


class CrossApprovalRequestLog(models.Model):
    request = models.ForeignKey(
        CrossApprovalRequest, on_delete=models.CASCADE, related_name="logs"
    )
    previous_status = models.CharField(max_length=20, blank=True)
    current_status = models.CharField(max_length=20)
    changed_by = models.ForeignKey("Dojo_User", on_delete=models.PROTECT)
    changed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-changed_at",)


class CrossApprovalDiscussion(models.Model):
    request = models.ForeignKey(
        CrossApprovalRequest, on_delete=models.CASCADE, related_name="discussions"
    )
    author = models.ForeignKey("Dojo_User", on_delete=models.PROTECT)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("created_at",)