import unittest
import importlib

saml_uri = importlib.import_module("dojo.settings.attribute-maps.saml_uri")

class TestSamlUriMap(unittest.TestCase):

    def test_map_exists(self):
        self.assertIsNotNone(saml_uri.MAP)

    def test_map_values(self):

        expected_values = {
            saml_uri.EDUPERSON_OID + '2': 'eduPersonNickname',
            saml_uri.EDUPERSON_OID + '9': 'eduPersonScopedAffiliation',
            saml_uri.EDUPERSON_OID + '11': 'eduPersonAssurance',
            saml_uri.EDUPERSON_OID + '10': 'eduPersonTargetedID',
            saml_uri.EDUPERSON_OID + '4': 'eduPersonOrgUnitDN',
            saml_uri.NOREDUPERSON_OID + '6': 'norEduOrgAcronym',
            saml_uri.NOREDUPERSON_OID + '7': 'norEduOrgUniqueIdentifier',
            saml_uri.NOREDUPERSON_OID + '4': 'norEduPersonLIN',
            saml_uri.EDUPERSON_OID + '1': 'eduPersonAffiliation',
            saml_uri.NOREDUPERSON_OID + '2': 'norEduOrgUnitUniqueNumber',
            saml_uri.NETSCAPE_LDAP + '40': 'userSMIMECertificate',
            saml_uri.NOREDUPERSON_OID + '1': 'norEduOrgUniqueNumber',
            saml_uri.NETSCAPE_LDAP + '241': 'displayName',
            saml_uri.UCL_DIR_PILOT + '37': 'associatedDomain',
            saml_uri.EDUPERSON_OID + '6': 'eduPersonPrincipalName',
            saml_uri.NOREDUPERSON_OID + '8': 'norEduOrgUnitUniqueIdentifier',
            saml_uri.NOREDUPERSON_OID + '9': 'federationFeideSchemaVersion',
            saml_uri.X500ATTR_OID + '53': 'deltaRevocationList',
            saml_uri.X500ATTR_OID + '52': 'supportedAlgorithms',
            saml_uri.X500ATTR_OID + '51': 'houseIdentifier',
            saml_uri.X500ATTR_OID + '50': 'uniqueMember',
            saml_uri.X500ATTR_OID + '19': 'physicalDeliveryOfficeName',
            saml_uri.X500ATTR_OID + '18': 'postOfficeBox',
            saml_uri.X500ATTR_OID + '17': 'postalCode',
            saml_uri.X500ATTR_OID + '16': 'postalAddress',
            saml_uri.X500ATTR_OID + '15': 'businessCategory',
            saml_uri.X500ATTR_OID + '14': 'searchGuide',
            saml_uri.EDUPERSON_OID + '5': 'eduPersonPrimaryAffiliation',
            saml_uri.X500ATTR_OID + '12': 'title',
            saml_uri.X500ATTR_OID + '11': 'ou',
            saml_uri.X500ATTR_OID + '10': 'o',
            saml_uri.X500ATTR_OID + '37': 'cACertificate',
            saml_uri.X500ATTR_OID + '36': 'userCertificate',
            saml_uri.X500ATTR_OID + '31': 'member',
            saml_uri.X500ATTR_OID + '30': 'supportedApplicationContext',
            saml_uri.X500ATTR_OID + '33': 'roleOccupant',
            saml_uri.X500ATTR_OID + '15': 'businessCategory',
            saml_uri.X500ATTR_OID + '3': 'commonName',
            saml_uri.X500ATTR_OID + '23': 'description',
            saml_uri.X500ATTR_OID + '8': 'organizationIdentifier',
            saml_uri.X500ATTR_OID + '11': 'countryName',
            saml_uri.X500ATTR_OID + '9': 'streetAddress',
            saml_uri.X500ATTR_OID + '17': 'postalCode',
            saml_uri.X500ATTR_OID + '39': 'physicalDeliveryOfficeName',
            saml_uri.X500ATTR_OID + '40': 'ou',
            saml_uri.X500ATTR_OID + '7': 'localityName',
            saml_uri.X500ATTR_OID + '5': 'serialNumber',
            saml_uri.X500ATTR_OID + '10': 'organizationName',
            saml_uri.X500ATTR_OID + '19': 'physicalDeliveryCountryName',
            saml_uri.X500ATTR_OID + '38': 'postOfficeBox',
            saml_uri.X500ATTR_OID + '21': 'generationQualifier',
            saml_uri.X500ATTR_OID + '4': 'surname',
            saml_uri.X500ATTR_OID + '41': 'title',
            saml_uri.X500ATTR_OID + '13': 'description'
        }
