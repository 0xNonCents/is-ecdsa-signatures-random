from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.privateKey import PrivateKey
import modified_sign
from ellipticcurve.utils.integer import RandomInteger
from base64 import b64decode
# Generate new Keys
privateKey = PrivateKey()
publicKey = privateKey.publicKey()

# Our fixed input
message = "My test message"

# Our desired output
desired_output = 64
available_options = 10064
tries = 0

# Generate Signature
randNum = RandomInteger.between(1, privateKey.curve.N - 1)
signature = modified_sign.sign(message, privateKey, randNum=randNum)
byte_slice = int.from_bytes(b64decode(signature.toBase64()), 'big')
tries = tries + 1
while desired_output != byte_slice % available_options:
    randNum = RandomInteger.between(1, privateKey.curve.N - 1)
    signature = modified_sign.sign(message, privateKey, randNum=randNum)
    byte_slice = int.from_bytes(b64decode(signature.toBase64()), 'big')
    tries = tries + 1

print("desired output found ", byte_slice, " in ", tries, " tries")

# To verify if the signature is valid
print(Ecdsa.verify(message, signature, publicKey))
