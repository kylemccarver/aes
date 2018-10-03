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

### mixColumns()
mixColumns() looks at each column of the state and multiplies it by a fixed matrix of the Galois field. Instead of doing the math and finding the polynomials ourselves, we opted to use the multiplication tables given to us. So instead of multiplying the byte by a number, we index into a multiplication table using our byte value as the index. For example, if we were to multiply byte 0x80 by 2, we would instead index into the MUL2 list with this syntax: MUL2[0x80]. Doing this is just a shortcut for doing the actual math described in the specifications. The fixed matrix for encryption utilizes multiplication tables 1, 2, and 3, while the decryption matrix utilizes tables 9, 11, 13, and 14. These tables are included in the constants.py file.

## addRoundKey()