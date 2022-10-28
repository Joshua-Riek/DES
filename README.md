## DES

This is my implementation of the Data Encryption Standard (DES), a symmetric-key block cipher published by the National Institute of Standards and Technology (NIST).

Encryption: `C = E(K1, P)`

Decryption: `P = D(K1, C)`

```Python
# A simple example of encrypting a string with DES!

key = 0x133457799bbcdff1

des = DES(key)
cyphertext = des.encrypt('Hello World!', key)
plaintext = des.decrypt(cyphertext, key) 
```

## Triple DES
Triple DES (3DES or TDES) is a symmetric-key block cipher, which applies the DES cipher algorithm three times to each data block.

Encryption: `C = E(K3, D(k2, E(K1, P)))`

Decryption: `P = D(K1, E(K2, D(K3, C)))`

```Python
# A simple example of encrypting bytes with Triple DES!

key1 = 0x133457799bbcdff1
key2 = 0x0123456789abcdef
key3 = 0xfedcba9876543210

des = TripleDES(key1, key2, key3)
cyphertext = des.encrypt(b'Hello World!')
plaintext = des.decrypt(cyphertext)
```