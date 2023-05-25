import unittest

from dojo.settings.attribute_maps.saml_uri import MAP, EDUPERSON_OID, NOREDUPERSON_OID, NETSCAPE_LDAP, UCL_DIR_PILOT, PKCS_9, X500ATTR_OID, UMICH, SCHAC



class TestSamlUriMap(unittest.TestCase):

    def test_map_exists(self):
        self.assertIsNotNone(MAP)

    def test_map_values(self):

        expected_values = {
            EDUPERSON_OID + '2': 'eduPersonNickname',
            EDUPERSON_OID + '9': 'eduPersonScopedAffiliation',
            EDUPERSON_OID + '11': 'eduPersonAssurance',
            EDUPERSON_OID + '10': 'eduPersonTargetedID',
            EDUPERSON_OID + '4': 'eduPersonOrgUnitDN',
            NOREDUPERSON_OID + '6': 'norEduOrgAcronym',
            NOREDUPERSON_OID + '7': 'norEduOrgUniqueIdentifier',
            NOREDUPERSON_OID + '4': 'norEduPersonLIN',
            EDUPERSON_OID + '1': 'eduPersonAffiliation',
            NOREDUPERSON_OID + '2': 'norEduOrgUnitUniqueNumber',
            NETSCAPE_LDAP + '40': 'userSMIMECertificate',
            NOREDUPERSON_OID + '1': 'norEduOrgUniqueNumber',
            NETSCAPE_LDAP + '241': 'displayName',
            UCL_DIR_PILOT + '37': 'associatedDomain',
            EDUPERSON_OID + '6': 'eduPersonPrincipalName',
            NOREDUPERSON_OID + '8': 'norEduOrgUnitUniqueIdentifier',
            NOREDUPERSON_OID + '9': 'federationFeideSchemaVersion',
            X500ATTR_OID + '53': 'deltaRevocationList',
            X500ATTR_OID + '52': 'supportedAlgorithms',
            X500ATTR_OID + '51': 'houseIdentifier',
            X500ATTR_OID + '50': 'uniqueMember',
            X500ATTR_OID + '19': 'physicalDeliveryOfficeName',
            X500ATTR_OID + '18': 'postOfficeBox',
            X500ATTR_OID + '17': 'postalCode',
            X500ATTR_OID + '16': 'postalAddress',
            X500ATTR_OID + '15': 'businessCategory',
            X500ATTR_OID + '14': 'searchGuide',
            EDUPERSON_OID + '5': 'eduPersonPrimaryAffiliation',
            X500ATTR_OID + '12': 'title',
            X500ATTR_OID + '11': 'ou',
            X500ATTR_OID + '10': 'o',
            X500ATTR_OID + '37': 'cACertificate',
            X500ATTR_OID + '36': 'userCertificate',
            X500ATTR_OID + '31': 'member',
            X500ATTR_OID + '30': 'supportedApplicationContext',
            X500ATTR_OID + '33': 'roleOccupant',
            X500ATTR_OID + '15': 'businessCategory',
            X500ATTR_OID + '3': 'commonName',
            X500ATTR_OID + '23': 'description',
            X500ATTR_OID + '8': 'organizationIdentifier',
            X500ATTR_OID + '11': 'countryName',
            X500ATTR_OID + '9': 'streetAddress',
            X500ATTR_OID + '17': 'postalCode',
            X500ATTR_OID + '39': 'physicalDeliveryOfficeName',
            X500ATTR_OID + '40': 'ou',
            X500ATTR_OID + '7': 'localityName',
            X500ATTR_OID + '5': 'serialNumber',
            X500ATTR_OID + '10': 'organizationName',
            X500ATTR_OID + '19': 'physicalDeliveryCountryName',
            X500ATTR_OID + '38': 'postOfficeBox',
            X500ATTR_OID + '21': 'generationQualifier',
            X500ATTR_OID + '4': 'surname',
            X500ATTR_OID + '41': 'title',
            X500ATTR_OID + '13': 'description'}
