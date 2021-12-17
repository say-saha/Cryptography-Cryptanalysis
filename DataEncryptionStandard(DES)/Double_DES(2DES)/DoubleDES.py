# Double DES is a collection of two DES encryptions(Block cipher) connected in serial way. In this encryption method, 
# we use two different keys of 64 bits (Including parity bits).
# Initially Double DES was introduced to eleminate the possibility of Bruteforce attack on the single DES. Later, we got to know 
# that Double DES is still vulnarable to a different attack known as meet-in-the-middle attack(MITM)
# (https://en.wikipedia.org/wiki/Meet-in-the-middle_attack)
# However, this threat is not that big, but its recommended to use Triple DES instead of Double DES.

# In this code I am using the python library "pycryptodome"(https://pycryptodome.readthedocs.io/en/latest/src/cipher/des.html) 
# to perform the DES encryption.
from Crypto.Cipher import DES

# Method for the Double DES encryption
def ddes_encryption(plain_text_path, key1_path, key2_path):
      # Reading the plain text from a text file & storing in a string "plain_text"
      plain_text_file = open(plain_text_path, 'r')
      plain_text = plain_text_file.read()
      plain_text_file.close()

      # Reading the first 64 bit key from a text file & storing in a string "key1"
      key1_file = open(key1_path, 'r')
      key1 = key1_file.read()
      key1_file.close()
      
      # Reading the second 64 bit key from a text file & storing in a string "key2"
      key2_file = open(key2_path, 'r')
      key2 = key2_file.read()
      key2_file.close()

      # Generating 2 cipher object with 2 keys for each statge of Double DES
      cipher1 = DES.new(str.encode(key1), DES.MODE_ECB) # For simplicity, using the ECB mode only
      cipher2 = DES.new(str.encode(key2), DES.MODE_ECB) # Encoding the keys, as the key is passed as a string, but DES accept bytearray.
      
      # Generating the intermediate cipher text after encrypting the plaintext 
      cipher_text_intermediate = cipher1.encrypt(str.encode(plain_text)) # The plain text in string format is encoded, as DES accept bytearray.
      # Generating the final cipher text after encrypting the intermediate cipher text(bytearray)
      cipher_text = cipher2.encrypt(cipher_text_intermediate)
      
      # Displaying the cipher text in bytearray format. To display the equivalent characters, the cipher text needs to be decoded.
      print("Cipher text:", cipher_text)
      
      # Storing the cipher text in a bytes file.
      cipher_file = open('2des_ciphertext.bytes', 'wb')
      cipher_file.write(cipher_text)
      cipher_file.close()

# Method for the Double DES decryption      
def ddes_decryption(cipher_text_path, key1_path, key2_path):
      # Reading the cipher text from the bytes file & storing in a variable "cipher_text"
      cipher_text_file = open(cipher_text_path, 'rb')
      cipher_text = cipher_text_file.read()
      cipher_text_file.close()

      # Reading the first 64 bit key from a text file & storing in a string "key1"
      key1_file = open(key1_path, 'r')
      key1 = key1_file.read()
      key1_file.close()
      
      # Reading the second 64 bit key from a text file & storing in a string "key2"
      key2_file = open(key2_path, 'r')
      key2 = key2_file.read()
      key2_file.close()

      # Generating 2 cipher object with 2 keys for each statge of Double DES
      cipher1 = DES.new(str.encode(key1), DES.MODE_ECB)
      cipher2 = DES.new(str.encode(key2), DES.MODE_ECB)
      
      # While decryption, the second key should be used for the first stage of decryption & then the first key should be used
      # Generating the intermediate plain text after decrypting the cipher text (in bytearray)
      plain_text_intermediate = cipher2.decrypt(cipher_text)
      # Generating the final plain text after decrypting the intermediate plain text(bytearray) & decoding to characters
      plain_text = (cipher1.decrypt(plain_text_intermediate)).decode("UTF-8")
      
      # Displaying the decrypted plain text.
      print("Decrypted plain text:", plain_text)
      
      # Storing the decrypted plain text in a text file.
      decrypted_plain_text_file = open('2des_decrypted_plaintext.txt', 'w')
      decrypted_plain_text_file.write(plain_text)
      decrypted_plain_text_file.close()



# Calling the encryption function to perform the Double DES encryption.
# Here, I am reading the plain text & keys from text files. 
# It's also possible to directly pass the plain text & keys to the function (Slight modification will be required in that case)
# Currently, in the plaintext file I am using only one block of plaintext(64 bits)
ddes_encryption("2DES_plaintext.txt", "2DES_key1.txt", "2DES_key2.txt")

# Calling the decryption function to perform the Double DES decryption.
ddes_decryption("2des_ciphertext.bytes", "2DES_key1.txt", "2DES_key2.txt")