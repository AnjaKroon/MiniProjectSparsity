# Sparsity Data Compression: MiniProject -- Cryptography One Time Pad
# Plaintext input
# Generate encrypted code
# "Send" encrypted code
# Decrypt code
# Display plain text message
# Plot the distirbution of plaintext characters 
# Plot distribution conditioned on a cipher character

import re
import numpy as np
import sys
import random
from array import array
import matplotlib.pyplot as plt

def toUnicode(txt):
    # given text as a string, transform it into an array with the corresponding unicode values
    return np.array([ord(char) for char in txt], dtype='int32')

def getKey(length):
    # randomly generate key with given length based on randomly allocating unicode values
    return np.random.randint(0, 256, length, dtype='int32')

def encryption(m, k):
    # XOR message and key to get the encrypted message
    return np.bitwise_xor(m,k)

def decryption(e, k):
    # XOR encrypted message and key to get the decrypted message
    return np.bitwise_xor(e,k)

def toPlainText(decrypt):
    # convert the unicode values into plaintext
    return ''.join(chr(value) for value in decrypt)

def testingOTP(m):
    print("The origional message is: ", m)
    message_length = len(m)

    # Take plain text and convert it into unicode. Store result in an array.
    message_unicode = toUnicode(m) 
    print("Converting plaintext message to unicode: ", message_unicode)

    # Get random key of length plaintext. Stored in an array. All elements are unicode characters            
    key_unicode = getKey(message_length)
    print("The random unicode key is: ", key_unicode)

    encrypted = encryption(message_unicode, key_unicode)
    print("The encrypted unicode message is:", encrypted)

    decrypted = decryption(encrypted, key_unicode)
    print("The decrypted unicode message is:", decrypted)

    decrypted_plaintext = toPlainText(decrypted)
    print("Converting decrypted unicode message to plaintext: ", decrypted_plaintext)
    return encrypted

def OTP(m):
    message_length = len(m)
    # Take plain text and convert it into unicode. Store result in an array.
    message_unicode = toUnicode(m) 
    # Get random key of length plaintext. Stored in an array. All elements are unicode characters            
    key_unicode = getKey(message_length)
    encrypted = encryption(message_unicode, key_unicode)
    decrypted = decryption(encrypted, key_unicode)
    decrypted_plaintext = toPlainText(decrypted)
    # print("Converting decrypted unicode message to plaintext: ", decrypted_plaintext)
    return encrypted

def txtfileToMessage(f):
    with open(f, 'r') as file:
        return file.read()
    
def getPDF_OrigMessage(s):
    char_count = {}
    total_chars = len(s)
    for char in s:
        char_count[char] = char_count.get(char, 0) + 1
    sorted_chars = sorted(char_count.items(), key=lambda x: x[1], reverse=True)
    chars, counts = zip(*sorted_chars)
    pdf_values = np.array(counts) / total_chars
    plt.figure(figsize=(10, 6))
    plt.bar(chars, pdf_values)
    plt.xlabel('Characters in Plaintext')
    plt.ylabel('Probability Density')
    plt.title('Unconditional Distribution of Plaintext Characters (PDF)')
    plt.xticks(fontsize=8)
    plt.show()
    return pdf_values

def getPDF_EncrData(data_array):
    value_count = {}
    total_values = len(data_array)
    for value in data_array:
        value_count[value] = value_count.get(value, 0) + 1
    
    sorted_values = sorted(value_count.items(), key=lambda x: x[1], reverse=True)
    values, counts = zip(*sorted_values)
    pdf_values = np.array(counts) / total_values

    plt.figure(figsize=(10, 6))
    plt.bar(values, pdf_values)
    plt.xlabel('Values in CipherText')
    plt.ylabel('Probability Density')
    plt.title('Empirical PDF of Characters in the Ciphertext')
    plt.xlim(0, 256)
    plt.show()
    return pdf_values

def entropy(pdf):
    return np.round(- np.sum(pdf * np.log2(pdf)), 2)

# message and ciphertext are arrays with unicode values as integers,
# cipher is an integer for a unicode character of interest
def getPDF_Joint(message, ciphertext, cipherchar):
    counter = 0
    for i in range(len(message)):
        if (message[i]) == ciphertext[i] == cipherchar:
            counter = counter +1                        # if message val = ciphertext val = cipherchar
    return (counter/len(message))                       # should correspond to P(M)

def getPDF_M(message, char):
    counter = 0
    for i in range(len(message)):
        if message[i] == char:
            counter = counter +1
    return (counter/len(message))

def getPDF_C(chiphertext, char):
    counter = 0
    for i in range(len(chiphertext)):
        if chiphertext[i] == char:
            counter = counter +1
    return (counter/len(chiphertext))

'''  
def getPDF_Cond(message, ciphertext):
    # Repeat for all possible characters and then you will get P(M=m|C=c), check sums to 1 and plot
    # Repeat for all possible characters
    # test_cipherchar = ord('t')
    orig_unicode = toUnicode(message)
    values = {}
    for char in range(0, 255):      # for every possible character, compute the pdf
        # print(test_cipherchar)
        # print("Displaying the conditional pdf P(M|C)")
        
        from_cond = getPDF_Joint(orig_unicode, ciphertext, char)
        # print("P(M=",test_cipherchar, "C=", test_cipherchar, ") is ", from_cond)

        from_C = getPDF_C(ciphertext, char)
        # print("P(C=", test_cipherchar, ") is ", from_C)

        from_M = getPDF_M(orig_unicode, char)
        # print("P(M=", test_cipherchar, ") is ", from_M)
        ans = from_cond/from_C
        new = {char : ans}      # x,y pairs for thr grapg
        values.update(new)
        # print("THEREFORE, P(M=", test_cipherchar, "|C=", test_cipherchar, ") is ", (from_cond/from_C))
    
    print(len(values), "should be 256, one for each entry")
    
    # make a list of x and y values to be plotting
    # x axis will be easy it will just be 0 to 255

    '''

def getPDF_Cond(message, ciphertext):
    # Repeat for all possible characters and then you will get P(M=m|C=c), check sums to 1 and plot
    orig_unicode = toUnicode(message)
    values = np.zeros(256)  # Initialize an array to store probabilities for each character
    for char in range(256):  # for every possible character, compute the pdf
        from_cond = getPDF_Joint(orig_unicode, ciphertext, char)
        from_C = getPDF_C(ciphertext, char)
        from_M = getPDF_M(orig_unicode, char)
        ans = round( (from_cond / from_C), 5)
        if (round(from_M, 1) != round(ans, 1)):
            print("error on char ", char, " from M is ", from_M, " from cond is ", ans)
        values[char] = ans  # Store the probability in the array

    print(len(values), "should be 256, one for each entry")
    sum_values = np.sum(values)
    print("should be 1 ", sum_values)
    plt.figure(figsize=(10, 6))
    plt.bar(range(256), values)
    plt.xlabel('Characters')
    plt.ylabel('Probability')
    plt.title('Conitional Prob. of Message Characters Cond. on Ciphertext Characters P(M = m | C = c)')
    plt.show()



def main():
    # Set of possible plaintext characters is anything in unicode
    # OTP algorithm where all intermediate steps are printed, used in testing
    test = "hello"
    encr_test = testingOTP(test)
    getPDF_OrigMessage(test)

    data = txtfileToMessage("./TaylorSwiftErasTourLyrics.txt")
    encr_data = OTP(data)
    print(encr_data)            # array of integers corresponding to unicode values

    print('Displaying the PDF of chars in the origional message ...')
    pdf_orig_message = getPDF_OrigMessage(data)
    entropy_orig_message= entropy(pdf_orig_message)
    print("The entropy of the origional message is: ", entropy_orig_message)

    print('Displaying the PDF of chars in the encrypted message ...')
    pdf_encr_data = getPDF_EncrData(encr_data)
    entropy_encr_data = entropy(pdf_encr_data)
    print("The entropy of the encrypted data is: ", entropy_encr_data)

    # getting P(M=m|C=c)

    # Repeat for all possible characters and then you will get P(M=m|C=c), check sums to 1 and plot
    # test_cipherchar = ord('t')

    # print(test_cipherchar)
    # print("Displaying the conditional pdf P(M|C)")
    # orig_unicode = toUnicode(data)

    # from_cond = getPDF_Joint(orig_unicode, encr_data, test_cipherchar)
    # print("P(M=",test_cipherchar, "C=", test_cipherchar, ") is ", from_cond)

    # from_C = getPDF_C(encr_data, test_cipherchar)
    # print("P(C=", test_cipherchar, ") is ", from_C)

    # from_M = getPDF_M(orig_unicode, test_cipherchar)
    # print("P(M=", test_cipherchar, ") is ", from_M)

    #print("THEREFORE, P(M=", test_cipherchar, "|C=", test_cipherchar, ") is ", (from_cond/from_C))

    getPDF_Cond(data, encr_data)

if __name__ == "__main__":
    main()
