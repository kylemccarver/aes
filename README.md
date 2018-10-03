# aes

## Dependencies
Python 3+

## Usage
python3 aes.py --keysize $KEYSIZE --keyfile $KEYFILE --inputfile $INPUTFILE --outputfile $OUTFILENAME --mode $MODE

## Explanation

### Input
To input the bytes of the input file into the program, we open it in binary mode and store them in a list. Then, we turn that list into a list of 4x4 blocks of bytes, each of which becomes the a that is encrypted or decrypted over a number of rounds. CMS padding is also applied if the number of bytes is not a multiple of 16. This processing occurs in the inputToState() method.

To input the bytes of the key file, we do the same first step as with the input file, but instead of splitting it into a list of blocks, we split it into a list of 4 byte words that will be XOR'd with the state during addRoundKey(). This processing occurs in the inputKeyBytes() method.

### Cipher (Encryption)
Each step of the cipher algorithm is implemented in the main() method. First the program receives the bytes of the input file and key file. Next, the key schedule is generated from input key. Then, on each state (4x4 array of bytes), the following steps occur:
* addRoundKey() - XOR the state with the first round key before the rounds start
Loop through Nr - 1 rounds (Nr = 10 if keysize is 128, 14 if keysize is 256) and do the following each round:
* subBytes() - substitute each byte in the state with the corresponding value in the lookup table (SBOX)
* shiftRows() - shift each row in the state based on its position in the block
* mixColumns() - for each column in the state, replace each byte with its value XOR'd with its corresponding value in a multiplication lookup table
* addRoundKey() - XOR the state with the round key in the key schedule corresponding to the current round

Now, outside the loop:
* subBytes() one more time
* shiftRows() one more time
* addRoundKey() XOR the state with the last round key
The resulting block is now encrypted and stored to be written to the file once the remaining blocks go through the same process.

### Inverse Cipher (Decryption)
The inverse cipher algorithm is also implemented in the main() method. The inputs are processed as before and the following steps occur:
* addRoundKey() - this time, XOR the state with the last round key before the rounds start
Loop through Nr - 1 rounds (Nr = 10 if keysize is 128, 14 if keysize is 256) in reverse order and do the following each round:
* shiftRows()
* subBytes() - substitute each byte using a different inverted table (SBOX_INV) from the encryption step
* mixColumns() - for each column in the state, replace each byte with its value XOR'd with its corresponding value in a multiplication lookup table. The lookup tables used in this step are different than the ones in the encryption mode.
* addRoundKey() - XOR the state with the round key in the key schedule corresponding to the current round

Now, outside the loop:
* shiftRows() one more time
* subBytes() one more time
* addRoundKey() XOR the state with the first round key
The resulting block is now decrypted and stored to be written to the file once the remaining blocks go through the same process.

### subBytes() and subBytesRow()
subBytes() substitutes each byte in the state by using its value as in index into the substitution lookup table. The code interprets the byte as an integer and uses bit masks to isolate the first four bits for the "x" index and the last four bits for the "y" index into the lookup table. When encrypting, we look up into the SBOX table, and when decrypting, we look up into the SBOX_INV table. These two tables are inverted and should replace the encrypted byte with the original byte and vice versa. subBytesRow() handles most of this logic and is a helper method that is used in the subBytes step and when generating the key schedule. These tables are included in the constants.py file.

### shiftRows()
shiftRows() shifts each row in the given state based on its position (row) within the state.

It starts by putting the state's first row in the new state, since the first row does not need to be shifted. Then, it makes use of collections.deque's rotate() method to apply a shift (left shift for encrypt, right shift for decrypt) to the other 3 rows (with the length of the shift determined by the row number), then adds each resulting row to the new state as well.

### mixColumns()
mixColumns() looks at each column of the state and multiplies it by a fixed matrix of the Galois field. Instead of doing the math and finding the polynomials ourselves, we opted to use the multiplication tables given to us. So instead of multiplying the byte by a number, we index into a multiplication table using our byte value as the index. For example, if we were to multiply byte 0x80 by 2, we would instead index into the MUL2 list with this syntax: MUL2[0x80]. Doing this is just a shortcut for doing the actual math described in the specifications. The fixed matrix for encryption utilizes multiplication tables 1, 2, and 3, while the decryption matrix utilizes tables 9, 11, 13, and 14. These tables are included in the constants.py file.

### addRoundKey()
addRoundKey() XOR's the state with the round key in the key schedule corresponding to the current round.

It first creates a "blank" 4x4 state of zeros, then gets the 4-word round key using the round number as the index for the key schedule. Then, in column order, each byte in the state is XOR'd with the next byte in the round key, and the result is stored in the new state in column order as well.

#### generateRoundKeys()
generateRoundKeys() is used to generate all of the round keys to be used for the key schedule.

Starting with the initial input key, it essentially just calls nextRoundKey() for each round and stores each round key in a list, with the number of rounds being 10 for a 128-bit key, or 14 for a 256-bit key. Once all round keys have been generated, it returns the list of all round keys.

#### nextRoundKey()
nextRoundKey() returns the next round key, based on the previous key, the round number, and the key size.

For a 128-bit (4 word) key size, word 0 of the next key is the result of XOR'ing the first word of the previous key with the result of calling g() on the last word of the previous key. Then, words 1-3 in the next key are obtained by XOR'ing the previous word with the corresponding word in the previous key.

For a 256-bit (8 word) key size, word 0 of the next key is obtained using the same process as the 128-bit method. Words 1-3 and 5-7 in the next key are also obtained in the same manner as with a 128-bit key. Word 4 is the exception, as it is the result of XOR-ing word 4 in the previous key with the result of calling subBytesRow() on the next key's word 3. This is the "extra step" required for 256-bit key expansion.

Once all words have been generated for the next key, they are returned as a list.

#### g()
g() is used as a helper method for the process of generating word 0 in nextRoundKey().

As per the key expansion algorithm, it first applies a 1-byte left shift to the given word using collections.deque's rotate() function. The next step calls subBytesRow() on that word. Finally, the resulting word is XOR'd with the round constant (obtained using rcon()) for the current round.

#### rcon()
rcon() is used to return Rcon[i] in the key expansion algorithm, which is the round constant for round i. It calls RC[i] (from constants.py) to get the first byte for Rcon[i], then uses 0x00 for the remining bytes. rcon() returns a 4-byte word for 128-bit key size, and an 8-byte word for 256-bit key size.

#### xor()
xor() is a helper method that returns the result of XOR'ing each byte from one word with the corresponding byte in another word. xor() is used frequently throughout the key expansion process, including g() and nextRoundKey().

xor() also makes use of byteToInt(), which converts each byte to an int (if it is not already an int) before the XOR operation.