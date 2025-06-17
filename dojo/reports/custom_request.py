from django.http import Http404, HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse, StreamingHttpResponse
from django.http import QueryDict
from dojo.models import Dojo_User


class CustomRequest(HttpRequest):
    def __init__(self, *args, **kwargs):
        super().__init__()
        self.GET = QueryDict(kwargs.get("query_dict_get", {}))
        self.META["QUERY_STRING"] = kwargs.get("query_string_meta", "")
        self.POST = kwargs.get("post_data", {})
        self.user = self.user = self.get_user(kwargs.get("user_id"))
        
    def get_user(self, user_id):
        if user_id:
            try:
                return Dojo_User.objects.get(id=int(user_id))
            except Dojo_User.DoesNotExist:
                raise Exception(f"User with id {user_id} does not exist.")
