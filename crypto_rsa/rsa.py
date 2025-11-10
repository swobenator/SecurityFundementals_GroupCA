#Author Bogdan Postolachi
#RSA Algorithm for encrypting Vignere Key

import random
import math
from math import gcd

#helper function for deciding if a number is prime
def is_prime(n):
    # Proper trial division up to sqrt(n); no early True inside the loop
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True

#function for creating a prime number
#Source: https://www.youtube.com/watch?v=D_PfV_IcUdA
def create_prime(min_val, max_val):
    prime = random.randint(min_val, max_val)

    while not is_prime(prime):
        prime = random.randint(min_val, max_val)

    return prime

def power(base, expo, m):
    res = 1
    base = base % m
    while expo > 0:
        if expo & 1:
            res = (res * base) % m
        base = (base * base) % m
        expo = expo // 2
    return res


#Source: https://www.geeksforgeeks.org/computer-networks/rsa-algorithm-cryptography/
def mod_inverse(e, phi):
    g, x, _ = egcd(e, phi)
    if g != 1:
        raise ValueError("mod_inverse does not exist")
    return x % phi




def create_keys():
    e_preferred = 65537
    while True:
        p = create_prime(5000, 90000)
        q = create_prime(5000, 90000)
        while p == q:
            q = create_prime(5000, 90000)

        n = p * q
        phi = (p - 1) * (q - 1)

        e = e_preferred
        if gcd(e, phi) == 1:
            try:
                d = mod_inverse(e, phi)
                return (e, n), (d, n), (p, q)
            except ValueError:
                # very rare; try new primes
                pass
        # else loop again


def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)



def encrypt_rsa(m, e, n):
    return power(m, e, n)


def decrypt_rsa(c, d, n):
    return power(c, d, n)

def rsa_encrypt_key(key_plaintext, public_key):

    #Encrypted the string character-by-character using RSA.
    #Returns a list of integers cipher blocks

    e, n = public_key
    cipher_blocks = []
    for ch in key_plaintext:
        m = ord(ch)
        if m >= n:
            # With our prime ranges, n will be huge compared to ord(ch), so this won't happen.
            raise ValueError("Plaintext block too large for RSA modulus")
        cipher_blocks.append(encrypt_rsa(m, e, n))
    return cipher_blocks


def rsa_decrypt_key(cipher_blocks, private_key):

    #Decrypt list of RSA cipher integers back to the original string

    d, n = private_key
    chars = []
    for c in cipher_blocks:
        m = decrypt_rsa(c, d, n)
        chars.append(chr(m))
    return ''.join(chars)


# End-to-end flows demonstrating RSA-encrypted string

def package_for_sender(message, vig_key_plain, public_key):

    #Sender side:
    #Encrypted the message with string using the plaintext
    #RSA-encrypted the string using the receiver public key
    #Returned (vig_ciphertext, rsa_encrypted_key_blocks)
    #The sender never transmits the string in plaintext

    rsa_key_blocks = rsa_encrypt_key(vig_key_plain, public_key)
    return rsa_key_blocks


def unpack_for_receiver(vig_ciphertext, rsa_key_blocks, private_key):

    #Receiver side:
    #RSA-decrypted the string using the receiver’s private key
    #Used the recovered key to decrypt the message
    #Returned the recovered plaintext

    recovered_key = rsa_decrypt_key(rsa_key_blocks, private_key)
    return recovered_key


# helpers to RSA-encrypt/decrypt a message
def rsa_encrypt_message(message, public_key):
    e, n = public_key
    return [encrypt_rsa(ord(ch), e, n) for ch in message]

def rsa_decrypt_message(cipher_blocks, private_key):
    d, n = private_key
    return ''.join(chr(decrypt_rsa(c, d, n)) for c in cipher_blocks)


if __name__ == "__main__":
    # generate RSA keys
    public, private, primes = create_keys()

    #example message and vignere key the key will be RSA-encrypted in transit
    message = "Hello!"
    vig_key_plain = "Bogdan"

    # RSA-encrypt/decrypt the message hardcoded for testing
    cipher_blocks = rsa_encrypt_message(message, public)
    recovered_message = rsa_decrypt_message(cipher_blocks, private)

    print("Cipher blocks:")
    print(cipher_blocks)
    print("Decrypted message:")
    print(recovered_message)
