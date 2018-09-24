import sys
import getopt

NB = 4

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
                mode = 0
            elif arg in ("decrypt", "d", "1"):
                mode = 1

    # do stuff with parameters


def subBytes():
    pass


def shiftRows(state):
    newState = [state[0]] # don't need to shift row 0
    from collections import deque # deque object used to simplify shifting
    for x in range(1,4):
        row = deque(state[x])
        row.rotate(-x) # shifts row left by x bytes
        newState += list(row)
    return newState


def mixColumns():
    pass


def addRoundKey():
    pass

if __name__ == "__main__":
    main(sys.argv[1:])
