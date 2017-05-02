import binascii, os
from Crypto.Cipher import AES

KEY = 'a0b8c7398c9363b3216ff1d001a1308e5f96a77dbf6bda2367f87519d80995fb'
IV =  os.urandom(16)

def encrypt(key, iv, plaintext):
    aes = AES.new(key, AES.MODE_CBC, iv, segment_size=128)
    plaintext = _pad_string(plaintext)
    encrypted_text = aes.encrypt(plaintext)
    return binascii.b2a_hex(encrypted_text).rstrip()


def decrypt(key, iv, encrypted_text):
    aes = AES.new(key, AES.MODE_CBC, iv, segment_size=128)
    encrypted_text_bytes = binascii.a2b_hex(encrypted_text)
    decrypted_text = aes.decrypt(encrypted_text_bytes)
    decrypted_text = _unpad_string(decrypted_text)
    return decrypted_text


def _pad_string(value):
    length = len(value)
    pad_size = 16 - (length % 16)
    return value.ljust(length + pad_size, '\x00')


def _unpad_string(value):
    while value[-1] == '\x00':
        value = value[:-1]
    return value

def prepare_for_save(IV, encrypted_value):
    binascii.b2a_hex(encrypted_text).rstrip()
    stored_value = "AES.1:" + binascii.b2a_hex(IV).rstrip() + ":" + encrypted_value
    return stored_value

def prepare_for_view(encrypted_value):
    encrypted_values = encrypted_value.split(":")

    type = encrypted_values[0]
    iv = binascii.a2b_hex(encrypted_values[1]).rstrip()
    value = encrypted_values[2]
    return decrypt(KEY, iv, value)

if __name__ == '__main__':
    input_plaintext = 'The answer is no'
    encrypted_text = encrypt(KEY, IV, input_plaintext)
    print encrypted_text
    decrypted_text = decrypt(KEY, IV, encrypted_text)
    print decrypted_text
    print prepare_for_save(IV, encrypted_text)
    print "*****"
    print prepare_for_view("AES.1:fff2e6659bef045f25f8249d36f58789:178e6f316b680b486e4e6b8cc79f589e")
    assert decrypted_text == input_plaintext
