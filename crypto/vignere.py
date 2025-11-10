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




def main():
    #pass
    message = "Hello My name is Danny"
    key = "BOGDAN"
    encrypted = encrypt_vignere(message, key)
    print("Encrypted:", encrypted)

    # Decrypt the message
    decrypted = decrypt_vignere(encrypted, key)
    print("Decrypted:", decrypted)


if __name__ == '__main__':
    main()