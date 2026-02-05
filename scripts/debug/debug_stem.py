#!/usr/bin/env python3
"""
Test with Stem's Ed25519 implementation which doesn't reduce modulo l
"""
import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')

from stem.util import ed25519

# Master public key
pubkey_bytes = bytes.fromhex("3bc09efcda967b643680765ff24c16b13a989ebc2a5bf9ff3a68b8db5142be71")

# Blinding nonce (the SHA3-256 hash)
blinding_nonce = bytes.fromhex("aa8714232ae4e557445d19d02ffbf60609a967592b61de473ddccb11aed94887")

# Stem's way of computing the blinding multiplier
b = 256
mult = 2 ** (b - 2) + sum(2 ** i * ed25519.bit(blinding_nonce, i) for i in range(3, b - 2))

print(f"Stem mult (big integer): {mult}")

# Decode the public key point
P = ed25519.decodepoint(pubkey_bytes)
print(f"Decoded P valid: {ed25519.isoncurve(P)}")

# Scalar multiply: blinded_pubkey = mult * P
blinded_point = ed25519.scalarmult(P, mult)
print(f"Blinded point valid: {ed25519.isoncurve(blinded_point)}")

# Encode back to bytes
blinded_pubkey = ed25519.encodepoint(blinded_point)
print(f"Stem blinded pubkey: {blinded_pubkey.hex()}")

# Compare to what we got with modular reduction
print()
print(f"RustBalance/NaCl result:   f4f173a013b2c680021412400947cccd213f55c60444921c889bad167cd2f5e4")
print(f"Stem result:               {blinded_pubkey.hex()}")
print(f"Match: {blinded_pubkey.hex() == 'f4f173a013b2c680021412400947cccd213f55c60444921c889bad167cd2f5e4'}")

# Also verify by using stem's _blinded_pubkey function directly
import stem.descriptor.hidden_service

# This is what OnionBalance calls
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# Actually, stem._blinded_pubkey takes the raw identity key bytes and a blinding_nonce
blinded_via_stem = stem.descriptor.hidden_service._blinded_pubkey(pubkey_bytes, blinding_nonce)
print(f"\nStem _blinded_pubkey:      {blinded_via_stem.hex()}")
