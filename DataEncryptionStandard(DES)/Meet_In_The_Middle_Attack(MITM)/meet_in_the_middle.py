# Meet In The Middle(MITM)(https://en.wikipedia.org/wiki/Meet-in-the-middle_attack) attack is an attack method to break the 
# Double DES encryption. It can be used as a chosen plaintext attack. In this method, the known plain text 
# (preferably a single 64 bit block) is encrypted with all possible 2^64 keys & stored the key along with corresponding 
# intermediate ciphertext in a table. Again decrypt the ciphertext of the known plain text with all possible keys & check if 
# the intermediate cipher text is present in the table or not. If present, the key2 is the current decryption key & key1 is the 
# corresponding key present in the table.

# However, its not possible to break a full 128 bit Double DES using this attack method with a single regular computer. 
# As it will take millions of years & around a million TB memory to break Double DES.

# Note: The below code can give multiple sets of keys as output due to collision. Decrypting the entire ciphertext with the 
# possible key candidates will help to validate & find the original keys.

# Note: In this code example, I am using the same 1 block of plaintext(64 bits) & keys (hardcoded last 6 bytes as 0 to save 
# time & memory) used in the Double DES example (https://github.com/say-saha/Cryptography-Cryptanalysis/tree/add-initial-readme/
# DataEncryptionStandard(DES)/Double_DES(2DES)). 
# Also, I used the same Double DES code to generate the ciphertext using the updated keys.

from Crypto.Cipher import DES
from itertools import product
import time
import string

# Method for DES encryption
def des_encryption(plain_text, key):
      # Creating DES cipher object
      cipher = DES.new(str.encode(key), DES.MODE_ECB)
      # Generating cipher text by encrypting the plain text
      cipher_text = cipher.encrypt(str.encode(plain_text))
      # Returning the cipher text in bytearray format
      return cipher_text      

# Method for DES decryption
def des_decryption(cipher_text, key):
      # Creating DES cipher object
      cipher = DES.new(str.encode(key), DES.MODE_ECB)
      # Generating plain text by decrypting the cipher text
      plain_text = cipher.decrypt(cipher_text)
      # Returning the plain text in bytearray format
      return plain_text    

# Method for executing the meet in the middle attack
def ddes_breaker(byte_length, plain_text_path, cipher_text_path):
      # Reading the plaintext from the text file
      plain_text_file = open(plain_text_path, 'r')
      plain_text = plain_text_file.read()
      plain_text_file.close()
      
      # Reading the ciphertext from the bytes file
      cipher_text_file = open(cipher_text_path, 'rb')
      cipher_text = cipher_text_file.read()
      cipher_text_file.close()

      # Declaring the collision table dictionary to store key1 & the corresponding cipher
      intermediate_cipher_dict = {} 

      # Taking the printible ascii values as key element
      possible_values = list(string.printable)
      
      # Storing attack start time
      start_time = time.time()
      # Generating all possible keys from possible values of n byte
      for c in product(possible_values, repeat=byte_length):
            # Filling rest bytes with 0
            key = ''.join(c) + "0"*(8-byte_length)
            # Generating intermediate cipher text by encrypting the plain text
            intermediate_cipher_text = des_encryption(plain_text, key)    
            # Storing the key & its corresponding intermediate cipher in the collision table dictionary
            intermediate_cipher_dict[key] = intermediate_cipher_text
            print ("\r" + "Time elapsed(s):" + str(time.time() - start_time), end='')
      
      # Converting the collision table dictionary into 2 lists of key & cipher 
      intermediate_key_list = list(intermediate_cipher_dict.keys())
      intermediate_cipher_list = list(intermediate_cipher_dict.values())
      print ("\r" + "Time elapsed(s):" + str(time.time() - start_time), end='')

      # Generating all possible keys from possible values of n byte
      for c in product(possible_values, repeat=byte_length):
            # Filling rest bytes with 0
            key = ''.join(c) + "0"*(8-byte_length)
            # Generating intermediate cipher text by decrypting the cipher text
            intermediate_cipher_text = des_decryption(cipher_text, key)
            
            # Checking if the intermediate cipher text is present in the collision table cipher list
            if intermediate_cipher_text in intermediate_cipher_list:
                  # If collision happens then key2 is the current key & key1 is the corresponding key of the cipher in the collision table
                  key2 = key
                  # Listing all keys from the collision table having the same cipher text (Collision)
                  key1_list = []
                  for i in range(len(intermediate_cipher_list)):
                        if intermediate_cipher_list[i] == intermediate_cipher_text:
                              key1_list.append(intermediate_key_list[i])
                  # Printing the possible sets of keys
                  for i in key1_list:
                        print("\nKey candidate found!\nKey 1:", i,"\nKey 2:", key2)
            print ("\r" + "Time elapsed(s):" + str(time.time() - start_time), end='')
            

# Calling the attack function to initiate the MITM attack
ddes_breaker(2, "2des_plaintext.txt", "2des_ciphertext.bytes")