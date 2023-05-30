# #!/usr/bin/python3

import sys
import bip44
import bip44.utils
import coincurve
import mnemonic
import io
import qrcode

listHoldAddress = []

def gen_from_seed(language, entropyStrength, seedPhrase, account_num=0):
    seedPhraseLength = len(seedPhrase.split(" "))
    
    # generate wallet w/ a single private/public key (address)
    wallet = bip44.Wallet(seedPhrase)
    secretKey, publicKey = wallet.derive_account("eth", account=account_num)
    
    # generate coincurve private key instance (to do stuff with...?)
    secretKey = coincurve.PrivateKey(secretKey)
    
    # coincurve instance validation
    if secretKey.public_key.format() != publicKey:
        print("\n** WARNING **: secretKey derived from coincurve DOES NOT match publicKey dervived from bip44")
    else:
        print("\n... note: coincurve validation success!")
        
    # derive publc address from public key?
    address = bip44.utils.get_eth_addr(publicKey)

    listHoldAddress.append(address)
    
    # print everything
    print("\nSeed Phrase ({} words):\n {}" .format(seedPhraseLength, seedPhrase))
    print("\naddress: {}" .format(address))
    print("secret: {}\n".format(secretKey.to_hex()))
    
def gen_eth_key(language, entropyStrength):
    # generate seed phrase
    mnemo = mnemonic.Mnemonic(language)
    seedPhrase = mnemo.generate(entropyStrength)
    seedPhraseLength = len(seedPhrase.split(" "))

    # generate wallet w/ a single private/public key (address)
    wallet = bip44.Wallet(seedPhrase)
    secretKey, publicKey = wallet.derive_account("eth", account=0)
    
    # generate coincurve private key instance (to do stuff with...?)
    secretKey = coincurve.PrivateKey(secretKey)
    
    # coincurve instance validation
    if secretKey.public_key.format() != publicKey:
        print("\n** WARNING **: secretKey derived from coincurve DOES NOT match publicKey dervived from bip44")
    else:
        print("\n... note: coincurve validation success!")
        
    # derive publc address from public key?
    address = bip44.utils.get_eth_addr(publicKey)

    listHoldAddress.append(address)
    
    # print everything
    print("\nSeed Phrase ({} words):\n {}" .format(seedPhraseLength, seedPhrase))
    print("\naddress: {}" .format(address))
    print("secret: {}\n".format(secretKey.to_hex()))

def obtain_address_qr():
    readData = None
    writeFile = None
    
    currentAddress = listHoldAddress[0]
    qr = qrcode.QRCode()
    qr.add_data(currentAddress)
    textStream = io.StringIO()
    qr.print_ascii(out=textStream)
    textStream.seek(0)
    with open("eth-address.txt", "w") as qrFile:
        readData = textStream.read()
        writeFile = qrFile.write(readData)

def help_me():
    with open("helpme.txt", "r") as readText:
        textToDisplay = readText.read()
        print(textToDisplay)

if __name__ == "__main__":
    language = str("english")
    entropyStrength = int(256)
    execute = None
    
    print("GO - genethkey.py")
    for command in sys.argv[1:]:
        if command == str("--generate") or command == str("-g"):
            execute = gen_eth_key(language, entropyStrength)
        if command == str("--qr") or command == str("-q"):
            execute = obtain_address_qr()
        if command == str("--help") or command == str("-h"):
            execute = help_me()
        if command == str("--restore-test") or command == str("-rt"):
            seed = "zero one two three four five six seven eight nine ten eleven thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty twenty-one twenty-two twenty-three"
            if not len(seed):
                print("\n** ERROR **: no seed phrase manually entered in code\n")
            else:
                for x in range(0,10):
                    print(f"account # {x}")
                    execute = gen_from_seed(language, entropyStrength, seed, x)
    print("DONE - genethkey.py")
