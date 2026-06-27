from django.db import IntegrityError
from rest_framework import serializers

from dojo.announcement.models import Announcement


class AnnouncementSerializer(serializers.ModelSerializer):

    class Meta:
        model = Announcement
        fields = "__all__"

    def create(self, validated_data):
        validated_data["id"] = 1
        try:
            return super().create(validated_data)
        except IntegrityError as e:
            if 'duplicate key value violates unique constraint "dojo_announcement_pkey"' in str(e):
                msg = "No more than one Announcement is allowed"
                raise serializers.ValidationError(msg)
            raise
