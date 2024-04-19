from rest_framework.test import APITestCase, APIClient
from django.urls import reverse
from dojo.models import Finding, Test, Test_Type, BurpRawRequestResponse
from rest_framework.authtoken.models import Token
from django.conf import settings

class APILimitReqRespPairsTest(APITestCase):
    """
    
    Test the MAX_REQRESP_FROM_API setting for /api/v2/findings/{id}/request_response/

    """

    fixtures = ['dojo_testdata.json']

    def setUp(self :object):
        token = Token.objects.get(user__username='admin')
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

    def assertReqrespValue(self :object, value :int, expect_notequal :bool=False) -> None:
        settings.MAX_REQRESP_FROM_API = value
        r = self.client.get(reverse('findings-list'), format='json')
        results = r.json()['results']
        # get finding with id 7        
        finding = self.getFinding(7, results)
        if expect_notequal:
            self.assertNotEqual(len(finding['request_response']['req_resp']), value)
        else:
            self.assertEqual(len(finding['request_response']['req_resp']), value)
        

    def getFinding(self :object, id :int, results :list) -> dict:
        for result in results:
            if result['id'] == id:
                return result            
        return None

    def test_reqresp(self: object) -> None:        
        self.assertReqrespValue(5)
        self.assertReqrespValue(10)
        self.assertReqrespValue(18) # actual number of reqresp
        self.assertReqrespValue(100, True) # more than the number in the request
        self.assertReqrespValue(-1, True) # default value of MAX_REQRESP_FROM_API
        self.assertReqrespValue(-100, True) # crazy negative value
