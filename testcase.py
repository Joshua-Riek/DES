from des import DES
from des import TripleDES
import unittest
import random
import string
import os


class TestDES(unittest.TestCase):
    def test_data(self):
        key = 0x133457799bbcdff1
        data = b'Hello World!'
        des = DES(key)
        cyphertext = des.encrypt(data)
        plaintext = des.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_random_data(self):
        key = random.randrange(0xffffffffffffffff)
        data = os.urandom(64)

        aes = DES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_str(self):
        key = 0x133457799bbcdff1
        data = 'Hello World!'

        des = DES(key)
        cyphertext = des.encrypt(data)
        plaintext = des.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_random_str(self):
        key = random.randrange(0xffffffffffffffff)
        data = ''.join(random.choice(string.ascii_letters) for _ in range(64))

        aes = DES(key)
        cyphertext = aes.encrypt(data)
        plaintext = aes.decrypt(cyphertext)

        self.assertEqual(data, plaintext)


class TestTripleDES(unittest.TestCase):
    def test_data(self):
        key1 = 0x133457799bbcdff1
        key2 = 0x0123456789abcdef
        key3 = 0xfedcba9876543210
        data = b'Hello World!'

        des = TripleDES(key1, key2, key3)
        cyphertext = des.encrypt(data)
        plaintext = des.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_random_data(self):
        key1 = random.randrange(0xffffffffffffffff)
        key2 = random.randrange(0xffffffffffffffff)
        key3 = random.randrange(0xffffffffffffffff)
        data = os.urandom(64)

        des = TripleDES(key1, key2, key3)
        cyphertext = des.encrypt(data)
        plaintext = des.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_str(self):
        key1 = 0x133457799bbcdff1
        key2 = 0x0123456789abcdef
        key3 = 0xfedcba9876543210
        data = 'Hello World!'

        des = TripleDES(key1, key2, key3)
        cyphertext = des.encrypt(data)
        plaintext = des.decrypt(cyphertext)

        self.assertEqual(data, plaintext)

    def test_random_str(self):
        key1 = random.randrange(0xffffffffffffffff)
        key2 = random.randrange(0xffffffffffffffff)
        key3 = random.randrange(0xffffffffffffffff)
        data = ''.join(random.choice(string.ascii_letters) for _ in range(64))

        des = TripleDES(key1, key2, key3)
        cyphertext = des.encrypt(data)
        plaintext = des.decrypt(cyphertext)

        self.assertEqual(data, plaintext)


if __name__ == '__main__':
    unittest.main()
