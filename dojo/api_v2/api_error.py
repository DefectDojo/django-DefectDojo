from rest_framework.exceptions import APIException


class ApiError(APIException):

    def __init__(self, detail, code=None):
        self.detail = detail
        self.code = code

    @classmethod
    def integrity_error(cls, contex):
        return cls(contex)
