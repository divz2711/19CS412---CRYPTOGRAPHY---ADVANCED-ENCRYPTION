# Cryptography---19CS412-Advanced -techqniques
# REG.NO :212221040042
# DATE : 29/02/24

# DES
DES using with different key values

# AIM:

To develop a simple A program to implement DES.

## DESIGN STEPS:

### Step 1:

Design of DES algorithnm 

### Step 2:

Implementation using C or pyhton code

### Step 3:

Testing algorithm with different key values. 

## PROGRAM:
```
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

def encrypt_message(message, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_message = message + b"\0" * (8 - len(message) % 8) # Padding the message if needed
    encrypted_message = cipher.encrypt(padded_message)
    return encrypted_message

def decrypt_message(encrypted_message, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.rstrip(b"\0") # Removing padding from decrypted message

def main():
    print("Message Encryption Using DES Algorithm\n")

    key = get_random_bytes(8)
    print("Secret Key:", key.hex())

    message = b"Secret Information"
    print("Original Message:", message.decode())

    encrypted_message = encrypt_message(message, key)
    print("Encrypted Message (in bytes):", encrypted_message.hex())

    decrypted_message = decrypt_message(encrypted_message, key)
    print("Decrypted Message:", decrypted_message.decode())

if __name__ == "__main__":
    main()

```

## OUTPUT:
![image](https://github.com/divz2711/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/121245222/64799c49-8e74-4707-b9d6-a479c2142ab5)


## RESULT:
The program is executed successfully

---------------------------------

# RSA
RSA using with different key values

# AIM:

To develop a simple C program to implement PlayFair Cipher.

## DESIGN STEPS:

### Step 1:

Design of RSA algorithnm 

### Step 2:

Implementation using C or pyhton code

### Step 3:

Testing algorithm with different key values. 

## PROGRAM:
```
from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from Crypto import Random
import base64

def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def encrypt(plain_text, key):
    plain_text = pad(plain_text)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(plain_text.encode('utf-8')))


def decrypt(encrypted_text, key):
    encrypted_text = base64.b64decode(encrypted_text)
    iv = encrypted_text[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_text[AES.block_size:])).decode('utf-8')


def main():
    secret_key = 'SaveethaEngineeringCollege'
    original_string = 'www.SaveethaEngineeringCollege.edu'

    # Derive key from secret_key using SHA1 hash
    sha = SHA1.new()
    sha.update(secret_key.encode('utf-8'))
    key = sha.digest()[:16]  # AES-128

    encrypted_string = encrypt(original_string, key)
    decrypted_string = decrypt(encrypted_string, key)

    print("URL Encryption Using AES Algorithm\n")
    print("Original URL:", original_string)
    print("Encrypted URL:", encrypted_string.decode('utf-8'))
    print("Decrypted URL:", decrypted_string)

if __name__ == "__main__":
    main()

```

## OUTPUT:

![image](https://github.com/divz2711/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/121245222/49c7e932-4106-4830-8e24-343dca9b2fc0)



## RESULT:
The program is executed successfully


---------------------------

# DIFFIE-HELLMAN
Deffie hellman algorithm to establish secret communication exchangine data over network

# AIM:

To develop a simple C program to implement Deffie-hellman.

## DESIGN STEPS:

### Step 1:

Design of Deffie-hellman key exchange algorithnm 

### Step 2:

Implementation using C or pyhton code

### Step 3:

Testing algorithm with different key values. 

## PROGRAM:
```
def main():
    p = 23  # publicly known (prime number)
    g = 5   # publicly known (primitive root)
    x = 4   # only Alice knows this secret
    y = 3   # only Bob knows this secret

    alice_sends = pow(g, x) % p
    bob_computes = pow(alice_sends, y) % p
    bob_sends = pow(g, y) % p
    alice_computes = pow(bob_sends, x) % p
    shared_secret = pow(g, x * y) % p

    print("Simulation of Diffie-Hellman key exchange algorithm\n")
    print("Alice Sends:", alice_sends)
    print("Bob Computes:", bob_computes)
    print("Bob Sends:", bob_sends)
    print("Alice Computes:", alice_computes)
    print("Shared Secret:", shared_secret)

    # shared secrets should match and equality is transitive
    if alice_computes == shared_secret and alice_computes == bob_computes:
        print("Success: Shared Secrets Match!", shared_secret)
    else:
        print("Error: Shared Secrets Do Not Match")

if __name__ == "__main__":
    main()

```

## OUTPUT:
![image](https://github.com/divz2711/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/121245222/36619970-3104-46c9-ab5b-7e9649ede651)

## RESULT:
The program is executed successfully

-------------------------------------------------
