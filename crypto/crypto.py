#Author: Bogdan Postolachi
#File created to handle server side encryption
#Vigenère Cipher

import random
import math
from math import gcd

#Source:
#https://www.youtube.com/watch?v=sxFObRNriUg
#used video for inspiration for the alphabet and index idea
alphabet_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

#lowercase alphabet
alphabet_lower = alphabet_upper.lower()

#dictionaries to map letter to index and dictionaries to map index to letter
#uppercase dictionaries
letter_index_upper = dict(zip(alphabet_upper, range(len(alphabet_upper))))
index_letter_upper = dict(zip(range(len(alphabet_upper)), alphabet_upper))

#lowercase dictionaries
letter_index_lower = dict(zip(alphabet_lower, range(len(alphabet_lower))))
index_letter_lower = dict(zip(range(len(alphabet_lower)), alphabet_lower))

#Created the key
#Logic and code around generating the key Inspired by:
#https://www.geeksforgeeks.org/dsa/vigenere-cipher/
#Original Code:
"""def generate_key(msg, key):
    key = list(key)
    if len(msg) == len(key):
        return key
    else:
        for i in range(len(msg) - len(key)):
            key.append(key[i % len(key)])
    return "".join(key)"""

#This funcrion will take the message and key as strings
#It's purpose is to repeat the encyption key so that it matches the length of the message
def create_key(message,key):

    #breakdown strings into list of characters
    key = list(key)
    message = list(message)

    #compare if message and key are already the same length
    if len(message) == len(key):
        #''.join(key) converts the key list back into a string and returns it
        return ''.join(key)
    else:
        #used while loop instead of for loop since the loop will continue until the key becomes the same lenght as the message
        #original_length will store the original length of the key
        original_length = len(key)
        #the while loop will continue adding characters until key length = mesage length
        i = 0
        while len(key) < len(message):
            key.append(key[i % original_length]) #i % orig_len cycles through the original key repeatedly using the modulus
            i += 1

    return ''.join(key) #join the list of characters back into a string


#function to define the encryption for the vignere cipher
def encrypt_vignere(message, key):
    #key = key.upper()
    #message = message.upper()
    key_stream = create_key(message,key) #reapeting the key so there's one key character per message character

    #variable to hold each encrypted letter as the loop is running
    enecrypted = []

    #preivious encrypt funstion inspired by:
    #https://www.youtube.com/watch?v=sxFObRNriUg
    """split_message = [message[i:i + len(key)] for i in range(0, len(message), len(key))]

    for each_split in split_message:
        i = 0
        for letter in each_split:
            number = (letter_index[letter] + letter_index[key[i]]) % 26
            enecrypted += index_letter[number]
            i += 1

    return enecrypted"""

    #enumerate(message) gives index i and the current character char
    #according to datacamp The enumerate() function is a Python built-in function that takes an iterable iterates through its items under the hood, and returns an enumerate object.
    #Source: https://www.datacamp.com/tutorial/python-enumerate-tutorial?utm_cid=19589720821&utm_aid=157156375191&utm_campaign=230119_1-ps-other%7Edsa%7Etofu_2-b2c_3-emea_4-prc_5-na_6-na_7-le_8-pdsh-go_9-nb-e_10-na_11-na&utm_loc=9181193-&utm_mtd=-c&utm_kw=&utm_source=google&utm_medium=paid_search&utm_content=ps-other%7Eemea-en%7Edsa%7Etofu%7Etutorial%7Epython&gad_source=1&gad_campaignid=19589720821&gbraid=0AAAAADQ9WsHnlENsU9XPI0nvM9O3oMU_f&gclid=CjwKCAiAlMHIBhAcEiwAZhZBUhykkZNZwjVZww-itk9myc7NjTGe18qdNrrmgCRWEVBJa6nEMJ8TOxoCJyMQAvD_BwE&dc_referrer=https%3A%2F%2Fwww.google.com%2F
    #Original code used for enumerate syntax:
    """drinks = ['tea', 'coffee', 'cappuccino', 'lemonade']
        enumerated_drinks = enumerate(drinks)"""
    #lopping throuch each character
    enumerated_message = enumerate(message)
    for i, char in enumerated_message:
        #if for uppercase letters
        if char in letter_index_upper:
            a = letter_index_upper[char] #look up the index of the message in the upppercase alphabet
            b = letter_index_upper[key_stream[i].upper()] #look up the index of the coresponding key character
            c = (a + b) % 26 #add the index letter of message to the index of the key letter then %26
            enecrypted.append(index_letter_upper[c]) #convert that index back into a letter using the reverse dictionary

        #Same logic but for lowercase letters
        elif char in letter_index_lower:
            a = letter_index_lower[char]
            b = letter_index_upper[key_stream[i].upper()]
            c = (a + b) % 26
            enecrypted.append(index_letter_lower[c])

        #if a character is not a letter it is just added on
        else:
            enecrypted.append(char)

    #join all the encrypted characters into a string and return ciphertext
    return ''.join(enecrypted)



#function to define the decryption for the vignere cipher
#same logic an encrypt_vignere just in reverse
def decrypt_vignere(message, key):
    #message = message.upper()
    key_stream = create_key(message, key)

    decrypted = []

    enumerated_message = enumerate(message)
    for i, char in enumerated_message:
        if char in letter_index_upper:
            a = letter_index_upper[char]
            b = letter_index_upper[key_stream[i].upper()]
            c = (a - b) % 26
            decrypted.append(index_letter_upper[c])

        elif char in letter_index_lower:
            a = letter_index_lower[char]
            b = letter_index_upper[key_stream[i].upper()]
            c = (a - b) % 26
            decrypted.append(index_letter_lower[c])

        else:
            decrypted.append(char)

    return ''.join(decrypted)



#Author Bogdan Postolachi
#RSA Algorithm for encrypting Vignere Key

#Used RSA used to exchange info between sender and reciver of the message

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


#encrypt the message using rsa public key
def encrypt_rsa(m, e, n):
    return power(m, e, n)

#decrypt cipher text using private key
def decrypt_rsa(c, d, n):
    return power(c, d, n)


def rsa_encrypt_key(key_plaintext, public_key):

    #Encrypted the Vigenere key (string) character-by-character using RSA
    #Returns a list of integers (cipher blocks)

    e, n = public_key
    cipher_blocks = []
    for ch in key_plaintext:
        m = ord(ch)
        if m >= n:
            # With prime ranges, n will be huge compared to ord(ch), so this won't happen.
            raise ValueError("Plaintext block too large for RSA modulus")
        cipher_blocks.append(encrypt_rsa(m, e, n))
    return cipher_blocks


def rsa_decrypt_key(cipher_blocks, private_key):

    #Decrypt list of RSA cipher integers back to the original key string.

    d, n = private_key
    chars = []
    for c in cipher_blocks:
        m = decrypt_rsa(c, d, n)
        chars.append(chr(m))
    return ''.join(chars)


# End-to-end flows demonstrating RSA-encrypted Vigenere key

def package_for_sender(message, vig_key_plain, public_key):

    #Sender side:
    #Encrypted the message with Vigenere using the plaintext key
    #RSA-encrypted the Vigenere key using the receiver public key
    #Returned (vig_ciphertext, rsa_encrypted_key_blocks)
    #The sender never transmits the Vigenère key in plaintext

    vig_ciphertext = encrypt_vignere(message, vig_key_plain)
    rsa_key_blocks = rsa_encrypt_key(vig_key_plain, public_key)
    return vig_ciphertext, rsa_key_blocks


def unpack_for_receiver(vig_ciphertext, rsa_key_blocks, private_key):

    #Receiver side:
    #RSA-decrypted the Vigenere key using the receiver’s private key
    #Used the recovered key to Vigenere-decrypt the message
    #Returned the recovered plaintext

    recovered_key = rsa_decrypt_key(rsa_key_blocks, private_key)
    plaintext = decrypt_vignere(vig_ciphertext, recovered_key)
    return plaintext


if __name__ == "__main__":
    # generate RSA keys
    public, private, primes = create_keys()

    #example message and Vigenère key (the key will be RSA-encrypted in transit)
    message = "Hello World!"
    vig_key_plain = "Bogdan"

    #create ciphertext plus RSA-encrypted key
    vig_ciphertext, rsa_key_blocks = package_for_sender(message, vig_key_plain, public)

    print("Sender Side:")
    print("Vigenere Ciphertext:")
    print(vig_ciphertext)
    print("\nRSA-encrypted Vigenère key (int blocks):")
    print(rsa_key_blocks)

    #decrypt the RSA key and then Vigenère-decrypt the message
    recovered_plain = unpack_for_receiver(vig_ciphertext, rsa_key_blocks, private)

    print("\nReciver Side:")
    print("Recovered Plaintext:")
    print(recovered_plain)