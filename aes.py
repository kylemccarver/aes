import sys
import getopt
from enum import Enum
from collections import deque
from constants import *

Mode = Enum('Mode', 'ENCRYPT DECRYPT')

def main(argv):
    # keySize will be either 128 or 256
    keySize = 0
    keyFile = None
    inputFile = None
    outputFile = None
    # mode will be 0 if encrypting, 1 if decrypting
    mode = 0

    if len(argv) < 10:
        print(("Usage: aes.py --keysize $KEYSIZE --keyfile $KEYFILE "
               "--inputfile $INPUTFILE --outputfile $OUTFILENAME --mode "
               "$MODE"))
        sys.exit()

    opts, args = getopt.getopt(argv, "", ["keysize=", "keyfile=",
                               "inputfile=", "outputfile=", "mode="])

    for opt, arg in opts:
        if opt == "--keysize":
            keySize = arg
        elif opt == "--keyfile":
            keyFile = open(arg, "rb")
        elif opt == "--inputfile":
            inputFile = open(arg, "rb")
        elif opt == "--outputfile":
            outputFile = open(arg, "wb")
        elif opt == "--mode":
            if arg in ("encrypt", "e", "0"):
                mode = Mode.ENCRYPT
            elif arg in ("decrypt", "d", "1"):
                mode = Mode.DECRYPT

    # do stuff with parameters
    state = inputToState(inputFile)
    if mode is Mode.ENCRYPT:
        state = subBytes(state, mode)
        state = shiftRows(state, mode)
        state = mixColumns(state, mode)
        state = addRoundKey(state, None)
    elif mode is Mode.DECRYPT:
        state = shiftRows(state, mode)
        state = subBytes(state, mode)
        state = addRoundKey(state, mode)
        state = mixColumns(state, mode)
    
    print(state)


def inputToState(input):
    """Takes the input file and stores its bytes as a list of 4x4 blocks of 
       data."""
    inputBytes = []
    byte = input.read(1)
    while byte:
        inputBytes.append(byte)
        byte = input.read(1)

    # Add padding if the length is not a multiple of 16; CMS method
    if len(inputBytes) % 16 != 0:
        remainder = 16 - len(inputBytes)
        for i in range(remainder):
            inputBytes.append(remainder.to_bytes(1, "big"))

    numberOfBlocks = int(len(inputBytes) / 16)
    inputIndex = 0
    state = []
    for i in range(numberOfBlocks):
        block = [[], [], [], []]
        for row in block:
            for j in range(4):
                row.append(inputBytes[inputIndex])
                inputIndex += 1
        state.append(block)

    return state


def xor(wordA, wordB):
    """Performs xor operation for each byte for two given words"""
    return [byteA ^ byteB for (byteA, byteB) in zip(wordA, wordB)]


def rcon(i):
    """Returns Rcon[i], the round constant for round i"""
    return [RC[i], 0x00, 0x00, 0x00]


def g(word, i):
    """g function used for generating first word in nextRoundKey"""
    row = deque(word)
    row.rotate(-1)
    gword = list(row)
    subBytesRow(gword, Mode.ENCRYPT)
    return xor(gword, rcon(i))


def nextRoundKey(prevKey, i):
    """Returns the next round key,
    based on the previous key and the round iteration number.
    """
    w0 = xor(prevKey[0], g(prevKey[3], i))
    w1 = xor(w0, prevKey[1])
    w2 = xor(w1, prevKey[2])
    w3 = xor(w2, prevKey[3])
    return [w0, w1, w2, w3]


def generateRoundKeys(key, keySize):
    """Returns a table of round keys, starting with the initial key"""
    roundKeys = [key]
    i = 1
    numRounds = 10 if keySize == 128 else 14
    while i <= numRounds:
        prevKey = roundKeys[i - 1]
        roundKeys.append(nextRoundKey(prevKey, i))
        i += 1
    return roundKeys


def subBytes(state, mode):
    """Substitutes each byte in the state with the corresponding entry in the 
       SBOX table."""
    subBytesState = state
    for block in subBytesState:
        for row in block:
            subBytesRow(row, mode)
    return subBytesState


def subBytesRow(row, mode):
    for i in range(4):
        byte = row[i]
        rowIndex = (ord(byte) & 0xF0) >> 4
        colIndex = (ord(byte) & 0x0F)
        if mode is Mode.ENCRYPT:
            row[i] = SBOX[rowIndex * 16 + colIndex].to_bytes(1, "big")
        elif mode is Mode.DECRYPT:
            row[i] = SBOX_INV[rowIndex * 16 +
                              colIndex].to_bytes(1, "big")


def shiftRows(state, mode):
    shiftRowsState = []
    for block in state:
        newBlock = [block[0]]  # don't need to shift row 0

        # newBlock[x] <- block[x] shifted by x bytes
        for x in range(1, 4):
            row = deque(block[x])
            if mode is Mode.ENCRYPT:
                row.rotate(-x)  # shift left
            elif mode is Mode.DECRYPT:
                row.rotate(x)   # shift right
            newBlock.append(list(row))

        shiftRowsState.append(newBlock)

    return shiftRowsState


def mixColumns(state, mode):
    """For each column in the state, replace each byte with its value
       multiplied by a fixed 4x4 matrix of integers."""
    mixColumnsState = []
    for block in state:
        newBlock = [[], [], [], []]
        for i in range(4):
            col = [int.from_bytes(block[0][i], "big"),
                   int.from_bytes(block[1][i], "big"),
                   int.from_bytes(block[2][i], "big"),
                   int.from_bytes(block[3][i], "big")]
            if mode is Mode.ENCRYPT:
                newBlock[0].append(MUL2[col[0]] ^ MUL3[col[1]] ^ col[2] ^ col[3])
                newBlock[1].append(col[0] ^ MUL2[col[1]] ^ MUL3[col[2]] ^ col[3])
                newBlock[2].append(col[0] ^ col[1] ^ MUL2[col[2]] ^ MUL3[col[3]])
                newBlock[3].append(MUL3[col[0]] ^ col[1] ^ col[2] ^ MUL2[col[3]])
            elif mode is Mode.DECRYPT:
                newBlock[0].append(MUL14[col[0]] ^ MUL11[col[1]] ^ MUL13[col[2]] ^ MUL9[col[3]])
                newBlock[1].append(MUL9[col[0]] ^ MUL14[col[1]] ^ MUL11[col[2]] ^ MUL13[col[3]])
                newBlock[2].append(MUL13[col[0]] ^ MUL9[col[1]] ^ MUL14[col[2]] ^ MUL11[col[3]])
                newBlock[3].append(MUL11[col[0]] ^ MUL13[col[1]] ^ MUL9[col[2]] ^ MUL14[col[3]])
        mixColumnsState.append(newBlock)

    return mixColumnsState


def addRoundKey(state, round):
    return state


if __name__ == "__main__":
    main(sys.argv[1:])
