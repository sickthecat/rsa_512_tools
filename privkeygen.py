#!/usr/bin/python3

# The following code was written by Wulf on #crypto (Libera)
#Modified by _SiCk @ afflicted.sh to drop the key into a .pem formatted file.

from math import gcd
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicNumbers,
    RSAPrivateNumbers,
    rsa_crt_iqmp,
    rsa_crt_dmp1,
    rsa_crt_dmq1,
)
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

def gcdext(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

def invert(a, n):
    g, x, __ = gcdext(a, n)
    if g != 1:
        raise ValueError("Arguments are not coprime")
    return x % n

e = 65537
# order doesn't matter:
p = 115733919514273107123584393261050157838699796410090632060096329519444848416597
q = 114538955737678332043511344817720090710169002820676417254048008431901325656187

n = p * q
pub_num = RSAPublicNumbers(e, n)
d = invert(e, (p - 1) * (q - 1))
iq = rsa_crt_iqmp(p, q)
dp = rsa_crt_dmp1(d, p)
dq = rsa_crt_dmq1(d, q)
prv_num = RSAPrivateNumbers(p, q, d, dp, dq, iq, pub_num)
prv = prv_num.private_key(default_backend())  # skip arg in recent versions

# Save the private key to a .pem file
with open("private_key.pem", "wb") as key_file:
    key_file.write(prv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
