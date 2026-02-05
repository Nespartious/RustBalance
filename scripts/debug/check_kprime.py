#!/usr/bin/env python3
"""Verify k_prime order of concatenation"""

import hashlib

prf = bytes.fromhex('0bbff02a667d29e6b94df6f117d691f6d46e9c4a8225e6271435fccb1208d175')
pers = b'Derive temporary signing key hash input'

print('PRF secret:', prf.hex())
print('Personalization:', pers.decode())
print()
print('stem way (prf || pers):', hashlib.sha512(prf + pers).digest()[:32].hex())
print('rust way (pers || prf):', hashlib.sha512(pers + prf).digest()[:32].hex())
print()
print('Rust k_prime from log:  3c64f4e8aa508e2d08a7bd2719a4744b4211c12a87220907cc0c586257123d4e')
