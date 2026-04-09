from django.urls import re_path

from . import views

urlpatterns = [
    re_path(r"^cicd_infrastructure/add$", views.new_cicd_infrastructure, name="add_cicd_infrastructure"),
    re_path(r"^cicd_infrastructure/(?P<ciid>\d+)/edit$", views.edit_cicd_infrastructure, name="edit_cicd_infrastructure"),
    re_path(r"^cicd_infrastructure/(?P<ciid>\d+)/delete$", views.delete_cicd_infrastructure, name="delete_cicd_infrastructure"),
    re_path(r"^cicd_infrastructure$", views.cicd_infrastructure, name="cicd_infrastructure"),
]
