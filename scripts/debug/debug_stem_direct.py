#!/usr/bin/env python3
"""
Minimal pure Python Ed25519 scalar multiplication for testing blinding.
Based on stem's ed25519.py which is from https://github.com/pyca/ed25519
"""
import hashlib
import operator

b = 256
q = 2 ** 255 - 19
l = 2 ** 252 + 27742317777372353535851937790883648493
int2byte = operator.methodcaller("to_bytes", 1, "big")

d = -121665 * pow(121666, q - 2, q) % q
I = pow(2, (q - 1) // 4, q)

def xrecover(y):
    xx = (y * y - 1) * pow(d * y * y + 1, q - 2, q)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x

By = 4 * pow(5, q - 2, q) % q
Bx = xrecover(By)
B = (Bx % q, By % q, 1, (Bx * By) % q)
ident = (0, 1, 1, 0)

def edwards_add(P, Q):
    (x1, y1, z1, t1) = P
    (x2, y2, z2, t2) = Q
    a = (y1-x1)*(y2-x2) % q
    b = (y1+x1)*(y2+x2) % q
    c = t1*2*d*t2 % q
    dd = z1*2*z2 % q
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    x3 = e*f
    y3 = g*h
    t3 = e*h
    z3 = f*g
    return (x3 % q, y3 % q, z3 % q, t3 % q)

def edwards_double(P):
    (x1, y1, z1, t1) = P
    a = x1*x1 % q
    b = y1*y1 % q
    c = 2*z1*z1 % q
    e = ((x1+y1)*(x1+y1) - a - b) % q
    g = -a + b
    f = g - c
    h = -a - b
    x3 = e*f
    y3 = g*h
    t3 = e*h
    z3 = f*g
    return (x3 % q, y3 % q, z3 % q, t3 % q)

def scalarmult(P, e):
    if e == 0:
        return ident
    Q = scalarmult(P, e // 2)
    Q = edwards_double(Q)
    if e & 1:
        Q = edwards_add(Q, P)
    return Q

def encodepoint(P):
    (x, y, z, t) = P
    zi = pow(z, q - 2, q)
    x = (x * zi) % q
    y = (y * zi) % q
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return bytes([
        sum([bits[i * 8 + j] << j for j in range(8)])
        for i in range(b // 8)
    ])

def bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1

def decodepoint(s):
    y = sum(2 ** i * bit(s, i) for i in range(0, b - 1))
    x = xrecover(y)
    if x & 1 != bit(s, b-1):
        x = q - x
    P = (x, y, 1, (x*y) % q)
    return P

# ========== Main test ==========

# Master public key
pubkey_bytes = bytes.fromhex("3bc09efcda967b643680765ff24c16b13a989ebc2a5bf9ff3a68b8db5142be71")

# Blinding nonce (the SHA3-256 hash before clamping)
blinding_nonce = bytes.fromhex("aa8714232ae4e557445d19d02ffbf60609a967592b61de473ddccb11aed94887")

# Stem's way of computing the blinding multiplier (equivalent to clamping)
# mult = 2^254 + sum(2^i * bit(h, i) for i in range(3, 254))
mult = 2 ** (b - 2)
for i in range(3, b - 2):
    mult += 2 ** i * bit(blinding_nonce, i)

print(f"Blinding multiplier mult = {mult}")
print(f"As little-endian bytes:    {mult.to_bytes(32, 'little').hex()}")

# Decode the public key point
P = decodepoint(pubkey_bytes)

# Scalar multiply: blinded_pubkey = mult * P (NOT mod l!)
blinded_point = scalarmult(P, mult)

# Encode back to bytes
blinded_pubkey = encodepoint(blinded_point)
print(f"\nStem-style blinded pubkey: {blinded_pubkey.hex()}")

# Compare to what RustBalance/NaCl produces (with mod l)
print(f"RustBalance result:        f4f173a013b2c680021412400947cccd213f55c60444921c889bad167cd2f5e4")
print(f"\nDo they match? {blinded_pubkey.hex() == 'f4f173a013b2c680021412400947cccd213f55c60444921c889bad167cd2f5e4'}")

# Check if Stem's result matches too
# Since mult > l, let's also see what mod l gives
mult_mod_l = mult % l
print(f"\nmult mod l = {mult_mod_l}")
blinded_mod_l = scalarmult(P, mult_mod_l)
print(f"With mod l blinding:       {encodepoint(blinded_mod_l).hex()}")

# The key insight: scalar multiplication is homomorphic over the group order!
# If P has order l, then (mult * P) == ((mult mod l) * P)
# So BOTH should give the same result!
print(f"\nmod l == non-mod l? {encodepoint(blinded_mod_l).hex() == blinded_pubkey.hex()}")
