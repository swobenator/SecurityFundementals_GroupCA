#Author: Bogdan Postolachi
#File created to handle server side encryption
#Vigenère Cipher

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

def create_key(message,key):

    #breakdown strings into list of characters
    key = list(key)
    message = list(message)

    #compare if message and key are already the same length
    if len(message) == len(key):
        return ''.join(key)
    else:
        #used while loop instead of for loop since the loop will continue until the key becomes the same lenght as the message
        orig_len = len(key)
        i = 0
        while len(key) < len(message):
            key.append(key[i % orig_len])
            i += 1

    return ''.join(key)



def encrypt(message, key):
    #key = key.upper()
    #message = message.upper()
    key_stream = create_key(message,key)

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

    for i, char in enumerate(message):
        if char in letter_index_upper:
            a = letter_index_upper[char]
            b = letter_index_upper[key_stream[i]]
            c = (a + b) % 26
            enecrypted.append(index_letter_upper[c])

        elif char in letter_index_lower:
            a = letter_index_lower[char]
            b = letter_index_upper[key_stream[i]]
            c = (a + b) % 26
            enecrypted.append(index_letter_lower[c])

        else:
            enecrypted.append(char)

    return ''.join(enecrypted)




def decrypt(message, key):
    #message = message.upper()
    key_stream = create_key(message, key)

    decrypted = []

    for i, char in enumerate(message):
        if char in letter_index_upper:
            a = letter_index_upper[char]
            b = letter_index_upper[key_stream[i]]
            c = (a - b) % 26
            decrypted.append(index_letter_upper[c])

        elif char in letter_index_lower:
            a = letter_index_lower[char]
            b = letter_index_upper[key_stream[i]]
            c = (a - b) % 26
            decrypted.append(index_letter_lower[c])

        else:
            decrypted.append(char)

    return ''.join(decrypted)




def main():
    #pass
    message = "Hello My name is Danny"
    key = "BOGDAN"
    encrypted = encrypt(message, key)
    print("Encrypted:", encrypted)

    # Decrypt the message
    decrypted = decrypt(encrypted, key)
    print("Decrypted:", decrypted)


if __name__ == '__main__':
    main()