import json
import unittest
from unittest.mock import Mock
from django.test import TestCase
from dojo.tools.api_sonarqube.api_client import SonarQubeAPI
from .test_api_sonarqube_importer import dummy_many_segurity_hotspots


class TestSonarQubeApi(TestCase):

    def session_manager_get(self, status_code):
        # mocke method post
        session_mock = Mock()
        response_mock_get = Mock()
        response_mock_get.status_code = status_code
        response_mock_get.json.return_value = dummy_many_segurity_hotspots()
        # mock method post
        session_mock.get.return_value = response_mock_get
        session_mock.auth = ("key123", "")
        session_mock.ok = True
        return session_mock

    def setUp(self):
        mock_tools_config = Mock()
        # tool config attr
        mock_tools_config.extras = []
        mock_tools_config.url = "http:localhost:9000/api/"
        mock_tools_config.authentication_type = "API"
        mock_tools_config.api_key = ""
        mock_tools_config.username = "username"
        mock_tools_config.password = "password test"
        # session manager
        mock_session = self.session_manager_get(200)
        self.sonar_qube_api = SonarQubeAPI(mock_tools_config)
        setattr(self.sonar_qube_api, "session", mock_session)
    
    def test_get_hotspots(self):
        print("init test")
        issue_key = "AYlhtIhyqRxoJ-kHfc60"
        hotspot = self.sonar_qube_api.get_hotspots(issue_key)
        assert hotspot["key"] == "AYlhtIhyqRxoJ-kHfc60"
