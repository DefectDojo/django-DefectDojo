from django.urls import path
from dojo.api_v2.security_posture.views import SecurityPosture 

# Manager cache url

urlpatterns = [
    path("api/v2/security_posture",
         SecurityPosture.as_view(),
         name='security_posture')
]