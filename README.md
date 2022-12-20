# AES_Cryptography_1
In this homework, you will perform encryption and decryption of a text message using a symmetric cipher that is combined with a password-based key derivation function. You need to write your codes in the Python programming language. You are expected to use pycryptodome package. You will write one Python script aes_cipher.py that takes arguments from the command line.

Encryption:

Encrypts a text message (m) using the given password (p). It has the following steps:

• Derive a key from the password using Scrypt (N=2**14, r=16, p=1) with random salt (128 bits). The key length (k) is determined by the user. The key will be used for encryption and decryption.

• Pad the input message using the PKCS7 algorithm to a length, that is a multiple of 16 bytes (128 bits).

• Encrypt the padded message using the AES with CBC mode of operation using the derived encryption key. Use a randomly generated 128-bit initialization vector (IV).

• Create a json file (f) that holds the randomly generated salt used for Scrypt, the randomly generated iv used for AES, and the produced ciphertext from AES.

Decryption:

Decrypts an encrypted message using the given password (p).

• Read the json file (f) given as input.

• Derive a key from the password using Scrypt (N=2**14, r=16, p=1) with the salt (from json).

• Decrypt the ciphertext using AES using the derived key and IV (from json).

Execution examples for encryption and decryption are given below. Make sure that you clearly display each calculated value as in the examples. You need to apply Base64 encoding for bytes-like objects to represent them in the readable form.

python aes_cipher.py enc -m "A secret message" -p "My password" -k 32 -f enc_info.json

Encryption result:

{"salt": "PnWgsTjRip9cRIhSowGCvg==", "iv": "uuhTXi+F7JjiBIngaDboig==", "ciphertext": "MDE9d1/a1AERKSu28P1/z12WTtHfLbj0eU7IMxF6sBg="}

python aes_cipher.py dec -p "My password" -k 32 -f enc_info.json

Plaintext:

A secret message

Note that you can run the above example by setting the salt and IV to the given values while checking whether you obtain the given result.
