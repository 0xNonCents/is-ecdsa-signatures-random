from hashlib import sha256
from ellipticcurve.signature import Signature
from ellipticcurve.math import Math
from ellipticcurve.utils.integer import RandomInteger
from ellipticcurve.utils.binary import numberFromByteString
from ellipticcurve.utils.compatibility import *


def sign(message, privateKey, randNum, hashfunc=sha256):
    byteMessage = hashfunc(toBytes(message)).digest()
    numberMessage = numberFromByteString(byteMessage)
    curve = privateKey.curve

    r, s, randSignPoint = 0, 0, None
    while r == 0 or s == 0:
        assert randNum < curve.N or randNum > 1
        randSignPoint = Math.multiply(curve.G, n=randNum, A=curve.A, P=curve.P, N=curve.N)
        r = randSignPoint.x % curve.N
        s = ((numberMessage + r * privateKey.secret) * (Math.inv(randNum, curve.N))) % curve.N
    recoveryId = randSignPoint.y & 1
    if randSignPoint.y > curve.N:
        recoveryId += 2

    return Signature(r=r, s=s, recoveryId=recoveryId)