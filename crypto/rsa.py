#Author Bogdan Postolachi
#RSA Algorithm for encrypting Vignere Key

import random
import math
from math import gcd

#helper function for deciding if a number is prime
#Code inspired by https://www.youtube.com/watch?v=D_PfV_IcUdA
#Original code:
"""def is_prime(number):
    if number < 2:
        return False
    for i in range(2, number // 2 + 1):
        if number % i == 0:
            return False
    return True
"""
#This loops through every integer from 2 to half the number
#if it finds no divisors it returns true
#My function is an improved version of that
#it rejects numbers smaller than 2
#it quickly handles even numbers
#it only checks odd numbers starting from 3
def is_prime(n):
    #automatically rejects numbers smaller that 2
    if n < 2:
        return False
    if n % 2 == 0: #check if n is even
        return n == 2
    i = 3 #set counter statrting at 3
    while i * i <= n: #runs as long as i * i is less than or equal to n
        if n % i == 0: #if n is divisible by i return false
            return False
        i += 2 #increment i
    return True

#function for creating a prime number
def create_prime(min_val, max_val): #pick 2 integers between min and max
    prime = random.randint(min_val, max_val)

    #check if the number is prime
    while not is_prime(prime):
        prime = random.randint(min_val, max_val)

    return prime

#Function to compute large exponentiations under a modulus
#Source: https://www.geeksforgeeks.org/computer-networks/rsa-algorithm-cryptography/
#Original Source Code:
"""def power(base, expo, m):
    res = 1
    base = base % m
    while expo > 0:
        if expo & 1:
            res = (res * base) % m
        base = (base * base) % m
        expo = expo // 2
    return res"""

def power(base, expo, m):
    res = 1 #variable for result
    base = base % m #base in modulo range
    while expo > 0: #loop until base becomes 0
        if expo & 1: #check if least significant bit is 1
            res = (res * base) % m #if it is multiply the current res by base
        base = (base * base) % m #each time square the base  move to the next binary bit of the exponent
        expo = expo // 2 #shifts the exponent one bit to the right
    return res


#Function to use the egcd
#x is the modular inverse of e mod φ
#O(log φ) time
#RSA encryption implementations use in practice because RSA numbers can be hundreds of digits long
#function’s goal is to find the modular inverse of e under phi
#compute the private key exponent
#Original Source Code for inspiration
"""def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m"""

#e is the public exponent
#phi is the modulus
def mod_inverse(e, phi):
    g, x, _ = egcd(e, phi) #call egcd
    #if g = 1 it means e and phi are coprime
    if g != 1: #check if g is equal to 1
        raise ValueError("mod_inverse does not exist") #if e and phi aren't coprime it is impossible to find d
    return x % phi


#generate RSA public and private keys
def create_keys():
    e_preferred = 65537 # constant public exponent
    while True: #infinite loop that keeps generating primes until a valid RSA key pair is found
        p = create_prime(5000, 90000) #generating 2 random prime numbers
        q = create_prime(5000, 90000)
        while p == q: #p and q cannot be equal so change q
            q = create_prime(5000, 90000)

        #calculate the modulus
        n = p * q
        phi = (p - 1) * (q - 1) #Euler’s totient function

        e = e_preferred #public key
        if gcd(e, phi) == 1: #check if e and phi are coprime
            try: #try block used because sometimes the mathematical step of finding d can fail
                d = mod_inverse(e, phi) #compute d
                return (e, n), (d, n), (p, q) #return keys and primes
            except ValueError:
                # try new primes
                pass


#Source: https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
#Original Source Code for Inspiration:
"""def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)"""

#Euclidean algorithm finds the greatest common divisor of two numbers a and b
#this also finds two coefficients x and y such that a×x+b×y= greates common divisors
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
