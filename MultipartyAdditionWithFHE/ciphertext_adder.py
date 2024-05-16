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

ctfiles = input('Enter the ciphertext files to add (comma separated): ').split(',')
ciphertexts = [DeserializeCiphertext(ctfile, JSON)[0] for ctfile in ctfiles]

result = cc.EvalAdd(ciphertexts[0], ciphertexts[1])
for i in range(2, len(ciphertexts)):
    result = cc.EvalAdd(result, ciphertexts[i])

filename = input('Resulting ciphertext is calculated. Enter the output file name: ')
SerializeToFile(filename, result, JSON)

print('Ciphertext written to', filename)
