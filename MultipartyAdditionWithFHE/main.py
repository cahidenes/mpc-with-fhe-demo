from openfhe import *
from math import log2

parameters = CCParamsBGVRNS()
parameters.SetPlaintextModulus(65537)

# NOISE_FLOODING_MULTIPARTY adds extra noise to the ciphertext before decrypting
# and is most secure mode of threshold FHE for BFV and BGV.
parameters.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY)

cc = GenCryptoContext(parameters)
# Enable Features you wish to use
cc.Enable(PKE)
cc.Enable(KEYSWITCH)
cc.Enable(LEVELEDSHE)
cc.Enable(ADVANCEDSHE)
cc.Enable(MULTIPARTY)

##########################################################
# Set-up of parameters
##########################################################

# Print out the parameters
# print(f"p = {cc.GetPlaintextModulus()}")
# print(f"n = {cc.GetCyclotomicOrder()/2}")
# print(f"lo2 q = {log2(cc.GetModulus())}")

############################################################
## Perform Key Generation Operation
############################################################

# print("Running key generation (used for source data)...")

publickeyfile = input('Enter the public key file (empty to generate without public key): ')
if publickeyfile:
    pubkey = DeserializePublicKey(publickeyfile, JSON)[0]
    kp = cc.MultipartyKeyGen(pubkey)
else:
    kp = cc.KeyGen()

if not kp.good():
    print("Key generation failed!")
    exit(1)

outputfilename = input('Key Pair generated. Enter the output file name for Public Key: ')

SerializeToFile(outputfilename, kp.publicKey, JSON)
print('Public Key written to ' + outputfilename)
print()


############################################################
## Encode source data
############################################################

number = int(input('Enter a number to encrypt: '))
plaintext = cc.MakePackedPlaintext([number])


############################################################
## Encryption
############################################################

encrypt_key = input('Enter the encrypt public key file: ')
publickey = DeserializePublicKey(encrypt_key, JSON)[0]

ciphertext = cc.Encrypt(publickey, plaintext)
cfile = input('Number encrypted. Enter output file for ciphertext: ')
SerializeToFile(cfile, ciphertext, JSON)
print('Ciphertext written to ' + cfile)
print()

############################################################
## EvalAdd Operation on Re-Encrypted Data
############################################################

# ciphertextAdd12 = cc.EvalAdd(ciphertext1, ciphertext2)
# ciphertextAdd123 = cc.EvalAdd(ciphertextAdd12, ciphertext3)

############################################################
## Decryption after Accumulation Operation on Encrypted Data with Multiparty
############################################################

# partial decryption by first party
cpfilename = input('Enter ciphertext to partially decrypt with private key: ')
lead = input('Is this lead? (y/N): ').lower() == 'y'
ciphertext = DeserializeCiphertext(cpfilename, JSON)[0]
if lead:
    ciphertextPartial = cc.MultipartyDecryptLead([ciphertext], kp.secretKey)[0]
else:
    ciphertextPartial = cc.MultipartyDecryptMain([ciphertext], kp.secretKey)[0]
pdfilename = input('Partial decryption is done. Enter the output file name for partial decryption: ')
SerializeToFile(pdfilename, ciphertextPartial, JSON)
print('Partial decryption written to ' + pdfilename)

