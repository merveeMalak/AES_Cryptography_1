#REFERENCES:
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
# https://pycryptodome.readthedocs.io/en/latest/src/random/random.html
# https://pycryptodome.readthedocs.io/en/latest/src/util/util.html
# https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html

import argparse   #used to command line parse 
import base64     #used to base64 encode and decode
import json       #used to read and write json file
from Crypto.Protocol.KDF import scrypt   #used to generate key
from Crypto.Util.Padding import pad, unpad   #used to padding and unpaddding
from Crypto.Cipher import AES       #used to AES encryption and decryption 
from Crypto.Random import get_random_bytes  #used to generate random bytes


#takes action, message, password, key length, file from command line and returns these values
def get_info():
    parser = argparse.ArgumentParser()
    parser.add_argument('type')
    parser.add_argument("-m", "--m", help="message")
    parser.add_argument("-p", "--p", help="password")
    parser.add_argument("-k", "--k", help="key len", type=int)    #bit or byte????
    parser.add_argument("-f", "--f", help="file",)
    args = parser.parse_args()
    if args.m == None:   #if operation is dec, message will be None
        return args.m, args.p.encode('ascii'), args.k, args.f , args.type
    return args.m.encode('ascii'), args.p.encode('ascii'), args.k, args.f , args.type


#Creates and returns a 128-bit salt value
def salt_generation():
    #salt = base64.b64decode("PnWgsTjRip9cRIhSowGCvg==".encode('ascii')) #example salt
    salt = get_random_bytes(16)
    return salt

#Creates and returns a 128-bit iv value
def iv_generation():
    #iv = base64.b64decode("uuhTXi+F7JjiBIngaDboig==".encode('ascii')) #example iv 
    iv = get_random_bytes(16)
    return iv


#parameters: p=password, k=key_length, salt=salt
#generates and returns a key 
def key_generation(p,k, salt):
    key = scrypt(p, salt=salt, key_len=k, N=2**14, r=16, p=1)
    return key 


#parameters: m=message, key=key, iv=iv
#Encrypts the message (m) with AES CBC mode.
#Returns the encrypted message (ciphertext).
def encryption(m, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(m, 16 ,style='pkcs7'))
    return ct

#parameters: f=file_name, salt=salt, iv=iv, ct=ciphertext
#Writes salt, iv and ciphertext to json file(f)
def write_json_file(f,salt, iv, ct):
    file_data = {"salt": base64.b64encode(salt).decode('ascii'),
        "iv": base64.b64encode(iv).decode('ascii'),
        "ciphertext": base64.b64encode(ct).decode('ascii')}
    with open(f, "w") as outfile:
        json.dump(file_data, outfile)
    print("Encryption result:\n" , file_data)

#parameter: f=file_name
#Reads the salt, iv and ciphertext values from the json file(f)
#Returns the salt, iv and ciphertext
def read_json_file(f):
    with open(f, 'r') as openfile:
        # Reading from json file
        data = json.load(openfile)
    return base64.b64decode(data['salt'].encode('ascii')), base64.b64decode(data['iv'].encode('ascii')), base64.b64decode(data['ciphertext'].encode('ascii'))


#parameters: key=key, iv=iv, ct=ciphertext
#Decrypts the ciphertext(ct) with AES CBC mode.
#Returns the plaintext (message)
def decryption(key, iv, ct):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ct), 16)
    return plaintext.decode()


def main():    
    m, p, k, f, operation = get_info()
    if not ((k == 16) or (k == 24) or (k ==32)):
        print("Key length must be 16 or 24 or 32")
        return
    if operation == 'enc':   #encryption operation 
        iv = iv_generation()
        salt = salt_generation()
        key = key_generation(p=p,k=k,salt=salt)
        ct = encryption(m=m, key=key, iv=iv)
        write_json_file(f=f,salt=salt, iv=iv, ct=ct)

    elif operation == 'dec':   #decryption operation
        salt, iv, ct = read_json_file(f)
        key = key_generation(p=p, k=k,salt=salt)
        plaintext = decryption(key=key, iv=iv, ct=ct)
        print("Plaintext:\n" + plaintext)
    else:
        print("Operation must be remarked!")

main()