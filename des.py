import binascii
import re


class DES(object):
    """
    Developed in the early 1970s at IBM and based on an earlier design
    by Horst Feistel, the algorithm was submitted to the National Bureau
    of Standards (NBS) following the agency's invitation to propose a
    candidate for the protection of sensitive, unclassified electronic
    government data.  with the number of unique possible key permutations
    being 2^56 (72,057,594,037,927,936) or 72 Quadrillion possible keys.

    Denoted as:
        Encryption: C = E(K1, P)
        Decryption: P = D(K1, C)

    Usage:
        des = DES(0x133457799bbcdff1)
        cyphertext = des.encrypt('Hello World!')
        plaintext = des.decrypt(cyphertext)
    """

    def __init__(self, key1):
        self.pc1 = [
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        ]

        self.pc2 = [
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        ]

        self.ip = [
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9,  1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        ]

        self.ip1 = [
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41,  9, 49, 17, 57, 25
        ]

        self.e = [
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        ]

        self.p = [
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
        ]

        self.sbox = [
            [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
             [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
             [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
             [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
            [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
             [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
             [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
             [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
            [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
             [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
             [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
             [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
            [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
             [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
             [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
             [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
            [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
             [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
             [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
             [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
            [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
             [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
             [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
             [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
            [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
             [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
             [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
             [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
            [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
             [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
             [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
             [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
        ]

        self.key1 = self.sub_keys(key1)

    @staticmethod
    def unpad(data):
        """
        Remove padding from data.

        @param data: Data to be un-padded
        @return: Data with removed padding
        """
        return data[:-data[-1]]

    @staticmethod
    def pad(data):
        """
        Append padding to data.

        @param data: Data to be padded
        @return: Data with padding
        """
        pad = 16 - (len(data) % 16)
        return data + bytearray(pad for _ in range(pad))

    @staticmethod
    def left_shift(c, d):
        """
        Moves bits one place to the left, two for the rounds in the iteration.

        @param c: Half of the first subkey
        @param d: Other half of the first subkey
        @return: First subkey shifted left
        """
        iteration = [3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15]
        c_list = [c]
        d_list = [d]
        for x in range(1, 17):
            c, d = c[1:] + c[0], d[1:] + d[0]
            if x in iteration:
                c_list.append(c[1:] + c[0])
                d_list.append(d[1:] + d[0])
            if x not in iteration:
                c_list.append(c)
                d_list.append(d)
        return ''.join(str(c_list[x]) + str(d_list[x]) for x in range(1, 17))

    def f(self, r, k):
        """
        The heart of this cipher is the Feistel function (f). This applies a
        48-bit key to the rightmost 32 bits to produce a 32-bit output.

        @param r: 32-bit data
        @param k: 48-bit Key
        @return: 32-bit data
        """
        e = ''.join(r[int(x) - 1] for x in self.e)
        xor = re.findall('.' * 6, ''.join('1' if k[x] != e[x] else '0' for x in range(0, 48)))
        f = ''.join('{:04b}'.format(
            self.sbox[x][int(xor[x][0] + xor[x][-1], 2)][int(xor[x][1:-1], 2)]) for x in range(len(xor)))
        return ''.join(f[int(x) - 1] for x in self.p)

    def sub_keys(self, key):
        """
        The function for generating all DES round subkeys.

        @param key: 64-bit key
        @return: List of generated subkeys
        """
        if abs(key) >= 0xffffffffffffffff:
            raise ValueError("Key can not be larger than 64-bits.")

        k = '{:064b}'.format(key)
        first_key = re.findall('.' * 7, ''.join(k[int(x) - 1] for x in self.pc1))
        C = ''.join(first_key[:int(len(first_key) / 2)])
        D = ''.join(first_key[int(len(first_key) / 2):])
        K = self.left_shift(C, D)
        return re.findall('.' * 48, ''.join(K[j - 1] for _ in range(1, 17) for j in self.pc2))[::-1]

    def encrypt_block(self, b, k):
        """
        Encrypt a block of data.

        @param b: Block to encrypt
        @param k: List of expanded keys
        @return: Encrypted block
        """
        B = '{:064b}'.format(int(b, 16))
        IP = re.findall('.' * 4, ''.join(B[int(x) - 1] for x in self.ip))
        L = list(range(17))
        L[0] = ''.join(IP[:int(len(IP) / 2)])
        R = list(range(17))
        R[0] = ''.join(IP[int(len(IP) / 2):])
        for x in range(1, 17):
            L[x] = R[x - 1]
            R[x] = ''.join('1' if L[x - 1][i] != self.f(R[x - 1], k[x - 17])[i] else '0' for i in range(0, 32))
        reverse = R[-1] + L[-1]
        IP = re.findall('.' * 8, ''.join(reverse[x - 1] for x in self.ip1))
        return ''.join('%02x' % int(x, 2) for x in IP)

    def decrypt_block(self, b, k):
        """
        Decrypt a block of data.

        @param b: Block to decrypt
        @param k: List of expanded keys
        @return: Decrypted block
        """
        B = '{:064b}'.format(int(b, 16))
        IP = re.findall('.' * 4, ''.join(B[x - 1] for x in self.ip))
        L = list(range(17))
        L[0] = ''.join(IP[:int(len(IP) / 2)])
        R = list(range(17))
        R[0] = ''.join(IP[int(len(IP) / 2):])
        for x in range(1, 17):
            L[x] = R[x - 1]
            R[x] = ''.join('1' if L[x - 1][i] != self.f(R[x - 1], k[x - 17])[i] else '0' for i in range(0, 32))
        reverse = R[-1] + L[-1]
        return ''.join(str(hex(int(x, 2))[2:]) for x in re.findall('.' * 4, ''.join(reverse[x - 1] for x in self.ip1)))

    def encrypt(self, data):
        """
        Encrypt data with the specified key.

        @param data: Data to encrypt
        @return: Encrypted data
        """
        if isinstance(data, str):
            return ''.join(self.encrypt_block(x, self.key1) for x in re.findall(
                '.' * 16, binascii.hexlify(self.pad(bytes(data, 'utf-8'))).decode()))
        elif isinstance(data, bytes):
            return b''.join(binascii.unhexlify(x.encode()) for x in [
                self.encrypt_block(x, self.key1) for x in re.findall(
                    '.' * 16, binascii.hexlify(self.pad(data)).decode())])
        else:
            raise TypeError("Invalid data type.")

    def decrypt(self, data):
        """
        Decrypt data with the specified key.

        @param data: Data to decrypt
        @return: Decrypted data
        """
        if isinstance(data, str):
            return self.unpad(bytes(''.join(chr(int(y, 16)) for x in [
                self.decrypt_block(z, self.key1) for z in re.findall(
                    '.' * 16, data)] for y in re.findall('.' * 2, x)), 'utf-8')).decode()
        elif isinstance(data, bytes):
            return self.unpad(b''.join(binascii.unhexlify(block.encode()) for block in [
                self.decrypt_block(x, self.key1) for x in re.findall(
                    '.' * 16, binascii.hexlify(data).decode())]))
        else:
            raise TypeError("Invalid data type.")


class TripleDES(DES):
    """
    Triple DES (3DES or TDES) is a symmetric-key block cipher, which
    applies the DES cipher algorithm three times to each data block.
    In general, Triple DES has three independent keys that have a length
    of 168 bits (three 56-bit DES keys), but due to a meet-in-the-middle
    attack vulnerability the effective security it provides is only 112 bits.

    Denoted as:
        Encryption: C = E(K3, D(K2, E(K1, P)))
        Decryption: P = D(K1, E(K2, D(K3, C)))

    Usage:
        des = TripleDES(0x133457799bbcdff1, 0x0123456789abcdef, 0xfedcba9876543210)
        cyphertext = des.encrypt('Hello World!')
        plaintext = des.decrypt(cyphertext)
    """
    def __init__(self, key1, key2, key3):
        super().__init__(key1)
        self.key2 = self.sub_keys(key2)
        self.key3 = self.sub_keys(key3)

    def encrypt(self, data):
        """
        Encrypt data with the three specified keys.

        @param data: Data to encrypt
        @return: Encrypted data
        """
        if isinstance(data, str):
            return ''.join(self.decrypt_block(x, self.key3) for x in [
                self.decrypt_block(x, self.key2) for x in [
                    self.encrypt_block(x, self.key1) for x in re.findall(
                        '.' * 16, binascii.hexlify(self.pad(bytes(data, 'utf-8'))).decode())]])
        elif isinstance(data, bytes):
            return b''.join(binascii.unhexlify(x.encode()) for x in [
                self.decrypt_block(x, self.key3) for x in [
                    self.decrypt_block(x, self.key2) for x in [
                        self.decrypt_block(x, self.key1) for x in re.findall(
                            '.' * 16, binascii.hexlify(self.pad(data)).decode())]]])
        else:
            raise TypeError("Invalid data type.")

    def decrypt(self, data):
        """
        Decrypt data with the three specified keys.

        @param data: Data to decrypt
        @return: Decrypted data
        """
        if isinstance(data, str):
            return self.unpad(bytes(''.join(chr(int(y, 16)) for x in [
                self.decrypt_block(x, self.key1) for x in [
                    self.encrypt_block(x, self.key2) for x in [
                        self.decrypt_block(x, self.key3) for x in re.findall(
                            '.' * 16, data)]]] for y in re.findall('.' * 2, x)), 'utf-8')).decode()
        elif isinstance(data, bytes):
            return self.unpad(b''.join(binascii.unhexlify(block.encode()) for block in [
                self.decrypt_block(x, self.key1) for x in [
                    self.encrypt_block(x, self.key2) for x in [
                        self.decrypt_block(x, self.key3) for x in re.findall(
                            '.' * 16, binascii.hexlify(data).decode())]]]))
        else:
            raise TypeError("Invalid data type.")
