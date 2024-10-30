import unittest
import importlib

django_saml_uri = importlib.import_module("dojo.settings.attribute-maps.django_saml_uri")

class TestSamlMap(unittest.TestCase):

    def test_identifier(self):
        self.assertEqual(django_saml_uri.MAP['identifier'], 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri')

    def test_fro(self):
        self.assertEqual(django_saml_uri.MAP['fro'][django_saml_uri.X500ATTR_OID + '3'], 'first_name')
        self.assertEqual(django_saml_uri.MAP['fro'][django_saml_uri.X500ATTR_OID + '4'], 'last_name')
        self.assertEqual(django_saml_uri.MAP['fro'][django_saml_uri.PKCS_9 + '1'], 'email')
        self.assertEqual(django_saml_uri.MAP['fro'][django_saml_uri.UCL_DIR_PILOT + '1'], 'uid')

    def test_to(self):
        self.assertEqual(django_saml_uri.MAP['to']['first_name'], django_saml_uri.X500ATTR_OID + '3')
        self.assertEqual(django_saml_uri.MAP['to']['last_name'], django_saml_uri.X500ATTR_OID + '4')
        self.assertEqual(django_saml_uri.MAP['to']['email'], django_saml_uri.PKCS_9 + '1')
        self.assertEqual(django_saml_uri.MAP['to']['uid'], django_saml_uri.UCL_DIR_PILOT + '1')
