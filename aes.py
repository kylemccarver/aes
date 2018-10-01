import sys
import getopt
from enum import Enum
from collections import deque
from constants import *

Mode = Enum('Mode', 'ENCRYPT DECRYPT')
KeySize = Enum('KeySize', 'B128 B256')

def main(argv):
    # keySize will be either 128 or 256
    keySize = None
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
            if arg in (128, "128"):
                keySize = KeySize.B128
            elif arg in (256, "256"):
                keySize = KeySize.B256
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

    keyBytes = [] # TODO: Remove this line when merging
    roundKeys = generateRoundKeys(keyBytes, keySize)
    keySchedule = [word for roundKey in roundKeys for word in roundKey]
    numRounds = 10 if keySize is KeySize.B128 else 14
    state = inputToState(inputFile)

    newState = []
    if mode is Mode.ENCRYPT:
        for block in state:
            newBlock = addRoundKey(block, keySchedule, 0)

            for r in range(1, numRounds):
                newBlock = subBytes(newBlock, mode)
                newBlock = shiftRows(newBlock, mode)
                newBlock = mixColumns(newBlock, mode)
                newBlock = addRoundKey(newBlock, keySchedule, r)

            newBlock = subBytes(newBlock, mode)
            newBlock = shiftRows(newBlock, mode)
            newBlock = addRoundKey(newBlock, keySchedule, numRounds)

            newState.append(newBlock)

    elif mode is Mode.DECRYPT:
        for block in state:
            newBlock = addRoundKey(block, keySchedule, numRounds)

            for r in reversed(range(1, numRounds)):
                newBlock = shiftRows(newBlock, mode)
                newBlock = subBytes(newBlock, mode)
                newBlock = addRoundKey(newBlock, keySchedule, r)
                newBlock = mixColumns(newBlock, mode)

            newBlock = shiftRows(newBlock, mode)
            newBlock = subBytes(newBlock, mode)
            newBlock = addRoundKey(newBlock, keySchedule, 0)

            newState.append(newBlock)

    stateToOutput(newState, outputFile)


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


def stateToOutput(state, outputFile):
    for block in state:
        for row in block:
            for byte in row:
                outputFile.write(byte.to_bytes(1, "big"))


def xor(wordA, wordB):
    """Performs xor operation for each byte for two given words"""
    return [byteA ^ byteB for (byteA, byteB) in zip(wordA, wordB)]


def rcon(i, keySize):
    """Returns Rcon[i], the round constant for round i"""
    rconBytes = [RC[i], 0x00, 0x00, 0x00]
    if keySize is KeySize.B256:
        rconBytes += [0x00, 0x00, 0x00, 0x00]
    return rconBytes


def g(word, i, keySize):
    """g function used for generating first word in nextRoundKey"""
    row = deque(word)
    row.rotate(-1)
    gword = subBytesRow(list(row), Mode.ENCRYPT)
    return xor(gword, rcon(i, keySize))


def nextRoundKey(prevKey, i, keySize):
    """Returns the next round key,
    based on the previous key and the round iteration number.
    """
    roundKey = []
    if keySize is KeySize.B128:
        w0 = xor(g(prevKey[3], i, keySize), prevKey[0])
        w1 = xor(w0, prevKey[1])
        w2 = xor(w1, prevKey[2])
        w3 = xor(w2, prevKey[3])
        roundKey = [w0, w1, w2, w3]
    elif keySize is KeySize.B256:
        w0 = xor(g(prevKey[7], i, keySize), prevKey[0])
        w1 = xor(w0, prevKey[1])
        w2 = xor(w1, prevKey[2])
        w3 = xor(w2, prevKey[3])
        w4 = xor(subBytesRow(w3, Mode.ENCRYPT), prevKey[4])
        w5 = xor(w4, prevKey[5])
        w6 = xor(w5, prevKey[6])
        w7 = xor(w6, prevKey[7])
        roundKey = [w0, w1, w2, w3, w4, w5, w6, w7]
    return roundKey


def generateRoundKeys(key, keySize):
    """Returns a table of round keys, starting with the initial key"""
    roundKeys = [key]
    i = 1
    numRounds = 10 if keySize is KeySize.B128 else 14
    while i <= numRounds:
        prevKey = roundKeys[i - 1]
        roundKeys.append(nextRoundKey(prevKey, i, keySize))
        i += 1
    return roundKeys


def subBytes(block, mode):
    """Substitutes each byte in the state with the corresponding entry in the 
       SBOX table."""
    return list(map(lambda r: subBytesRow(r, mode), block))


def subBytesRow(row, mode):
    subRow = []
    for i in range(len(row)):
        byte = str(row[i])
        rowIndex = (ord(byte) & 0xF0) >> 4
        colIndex = (ord(byte) & 0x0F)
        if mode is Mode.ENCRYPT:
            subRow.append(SBOX[rowIndex * 16 + colIndex].to_bytes(1, "big"))
        elif mode is Mode.DECRYPT:
            subRow.append(SBOX_INV[rowIndex * 16 +
                              colIndex].to_bytes(1, "big"))
    return subRow


def shiftRows(block, mode):
    newBlock = [block[0]]  # don't need to shift row 0

    # newBlock[x] <- block[x] shifted by x bytes
    for x in range(1, 4):
        row = deque(block[x])
        if mode is Mode.ENCRYPT:
            row.rotate(-x)  # shift left
        elif mode is Mode.DECRYPT:
            row.rotate(x)   # shift right
        newBlock.append(list(row))

    return newBlock


def mixColumns(block, mode):
    """For each column in the state, replace each byte with its value
       multiplied by a fixed 4x4 matrix of integers."""
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

    return newBlock


def addRoundKey(block, keySchedule, round):
    newBlock = []
    idx = round * 4
    roundKey = [keySchedule[idx], keySchedule[idx+1], keySchedule[idx+2], keySchedule[idx+3]]
    for x in range(4):
        newRow = []
        for y in range(4):
            newRow.append(block[y][x] ^ roundKey[x][y])
        newBlock.append(newRow)
    return newBlock


if __name__ == "__main__":
    main(sys.argv[1:])
