import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dojo.settings.settings')
import django
django.setup()
import os
from django.conf import settings
from django.core import management


import unittest
from unittest.mock import patch, Mock
import unittest.mock as mock
from dojo.github import reopen_external_issue_github
from dojo.github import close_external_issue_github
from dojo.models import Engagement, Product, GITHUB_PKey, GITHUB_Issue

class TestGitHub(unittest.TestCase):

    #Decorador @patch para simular el comportamiento de la clase GITHUB_PKey en la función.
    @patch('dojo.github.GITHUB_PKey.objects.filter')
     #Se define test que verifica el comportamiento de la función reopen_external_issue_github() cuando no se proporciona información de Github.
    def test_reopen_external_issue_github_no_github_info(self, mock_pkey_filter):
        #Se configura el comportamiento de la función filter() de la clase GITHUB_PKey simulada.
        #En este caso, cuando se llame a count() se devuelve 0, lo que indica que no se encontró información de Github.
        mock_pkey_filter.return_value.count.return_value = 0
        prod = Mock()
        find = Mock()
        eng = Mock()
        note = "This issue has been reopened"
        # Se llama a la función que se quiere testear.
        result = reopen_external_issue_github(find, note, prod, eng)
        # Se verifica que el resultado es None, lo que indica que la función ha funcionado correctamente.
        self.assertIsNone(result)

    # Decoradores @patch para simular el comportamiento de las clases y funciones necesarias en la función.
    @patch('dojo.github.GITHUB_PKey.objects.filter')
    @patch('dojo.github.GITHUB_PKey.objects.get')
    @patch('dojo.github.GITHUB_Issue.objects.get')
    @patch('dojo.github.Github')
    # Se define un test que verifica el comportamiento de la función reopen_external_issue_github() cuando se proporciona información de Github.
    def test_reopen_external_issue_github_success(self, mock_github, mock_issue_get, mock_pkey_get, mock_pkey_filter):
         # Se configura el comportamiento de la función filter() de la clase GITHUB_PKey simulada.
        # En este caso, cuando se llame a count() se devuelve 1, lo que indica que se encontró información de Github.
        mock_pkey_filter.return_value.count.return_value = 1
        # Se configura el comportamiento de la función get() de la clase GITHUB_PKey simulada.
        # En este caso, se devuelve un objeto Mock con los valores necesarios para que la función reopen_external_issue_github() funcione correctamente.
        mock_pkey_get.return_value = Mock(git_conf=Mock(api_key='dummy_api_key'), git_project='dummy_project')
        # Se configura el comportamiento de la función get() de la clase GITHUB_Issue simulada.
        # En este caso, se devuelve un objeto Mock con los valores necesarios para que la función reopen_external_issue_github() funcione correctamente.
        mock_issue_get.return_value = Mock(issue_id='1')
        # Se configura el comportamiento de la función get_repo() de la clase Github simulada.
        # En este caso, se devuelve un objeto Mock con los valores necesarios para que la función reopen_external_issue_github() funcione correctamente.
        mock_github.return_value.get_repo.return_value.get_issue.return_value = Mock(state='closed')
        # Se crean mocks para las variables requeridas por la función.
        prod = Mock()
        find = Mock()
        eng = Mock()
        note = "This issue has been reopened"
        # Se llama a la función que se quiere testear.
        result = reopen_external_issue_github(find, note, prod, eng)
        # Se verifica que el resultado es None, lo que indica que la función ha funcionado correctamente.
        self.assertIsNone(result)
