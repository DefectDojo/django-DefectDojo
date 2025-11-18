from rest_framework import serializers
from dojo.models import Alerts

class AlertsSerializers(serializers.ModelSerializer):
    
    class Meta:
        model = Alerts
        fields = ['id', 'user_id', 'title', 'description',  'source', 'url', 'created']