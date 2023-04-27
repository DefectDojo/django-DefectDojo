# Importamos el módulo unittest que nos permitirá definir los casos de prueba.
import unittest

# Importamos la variable django_saml_uri del módulo attribute_maps dentro del paquete settings.
from dojo.settings.attribute_maps import django_saml_uri

# Definimos una clase de prueba que hereda de unittest.TestCase.
class TestSamlMap(unittest.TestCase):

    # Definimos el método de prueba test_identifier para verificar que la clave 'identifier' del diccionario MAP es igual a un valor esperado.
    def test_identifier(self):
        self.assertEqual(django_saml_uri.MAP['identifier'], 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri')
    
    # Definimos el método de prueba test_fro para verificar que las claves correspondientes a los atributos de usuario en el diccionario MAP son iguales a los valores esperados.
    def test_fro(self):
        self.assertEqual(django_saml_uri.MAP['fro'][django_saml_uri.X500ATTR_OID + '3'], 'first_name')
        self.assertEqual(django_saml_uri.MAP['fro'][django_saml_uri.X500ATTR_OID + '4'], 'last_name')
        self.assertEqual(django_saml_uri.MAP['fro'][django_saml_uri.PKCS_9 + '1'], 'email')
        self.assertEqual(django_saml_uri.MAP['fro'][django_saml_uri.UCL_DIR_PILOT + '1'], 'uid')
    
    # Definimos el método de prueba test_to para verificar que las claves correspondientes a los atributos de usuario en el diccionario MAP son iguales a los valores esperados.
    def test_to(self):
        self.assertEqual(django_saml_uri.MAP['to']['first_name'], django_saml_uri.X500ATTR_OID + '3')
        self.assertEqual(django_saml_uri.MAP['to']['last_name'], django_saml_uri.X500ATTR_OID + '4')
        self.assertEqual(django_saml_uri.MAP['to']['email'], django_saml_uri.PKCS_9 + '1')
        self.assertEqual(django_saml_uri.MAP['to']['uid'], django_saml_uri.UCL_DIR_PILOT + '1')
