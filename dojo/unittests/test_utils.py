from django.test import TestCase
from dojo.utils import dojo_crypto_encrypt, prepare_for_view


class TestUtils(TestCase):
    def test_encryption(self):
        test_input = "Hello World!"
        encrypt = dojo_crypto_encrypt(test_input)
        test_output = prepare_for_view(encrypt)
        self.assertEqual(test_input, test_output)
