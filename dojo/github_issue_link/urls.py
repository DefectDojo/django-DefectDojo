from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^webhook', views.webhook, name='web_hook'),
    url(r'^github/add', views.new_github, name='add_github'),
    url(r'^github/(?P<jid>\d+)/edit$', views.edit_github,
        name='edit_github'),
    url(r'^github/(?P<tid>\d+)/delete$', views.delete_github,
        name='delete_github'),
    url(r'^github$', views.github, name='github'),
    url(r'^github/express', views.express_new_github, name='express_github')]
