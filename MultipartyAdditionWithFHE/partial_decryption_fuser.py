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

pdfilenames = input('Enter partial decryption filenames (comma separated): ').split(',')
partial_decryptions = [DeserializeCiphertext(pdfilename, JSON)[0] for pdfilename in pdfilenames]

# partial decryption are combined together
plaintext = cc.MultipartyDecryptFusion(partial_decryptions)
plaintext.SetLength(1)
print('Fusion is done. Resulting plaintext:', str(plaintext)[2:-6])

