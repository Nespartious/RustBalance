#!/usr/bin/env python3
"""Verify the blinded Ed25519 signature computation"""

import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

# Values from RustBalance debug output:
# blinded_pubkey: e22bd88bcff2e955c20849244ec82899dbdddda778ba55fa12d0180be5b8e2b5
# blinded_private_scalar: 1038ed706b076e00913258e005263fdf8be4e3dc4c682b59aa86eb8f04aef203
# prf_secret: 0bbff02a667d29e6b94df6f117d691f6d46e9c4a8225e6271435fccb1208d175
# k_prime: 3c64f4e8aa508e2d08a7bd2719a4744b4211c12a87220907cc0c586257123d4e
# r_hash: 5eabd5bc41c9d78ca4adfc143a83b0d315f974d56426c73fa5544a92fba09bc396dfbb756bbf636d434c0b9a614c74a8416d4956a9254efae3c21cb663761e36
# r: 08a15b890e27ed842de12c1bd06b8caa5a9f7989c5b46c60e1dbd0ea9cd8910a
# R: eddb3684db72a89927db18db9c1e1717d1954ead33406688cdcd64249eaf4395
# s: 339fe24d0f3820ecaefcf6c620d0c4e9363fd8004e97b6c75aa840d62fdde10c

L = 2**252 + 27742317777372353535851937790883648493

def bytes_to_int(b):
    return int.from_bytes(b, 'little')

def int_to_bytes32(n):
    return (n % L).to_bytes(32, 'little')

# Verify k' derivation
# stem does: k' = SHA512(PRF_SECRET || "Derive temporary signing key hash input")[:32]
prf_secret = bytes.fromhex('0bbff02a667d29e6b94df6f117d691f6d46e9c4a8225e6271435fccb1208d175')
personalization = b"Derive temporary signing key hash input"
k_prime_input = prf_secret + personalization
k_prime_computed = hashlib.sha512(k_prime_input).digest()[:32]
print(f'k_prime computed: {k_prime_computed.hex()}')
rust_k_prime = bytes.fromhex('3c64f4e8aa508e2d08a7bd2719a4744b4211c12a87220907cc0c586257123d4e')
print(f'k_prime from Rust: {rust_k_prime.hex()}')
print(f'k_prime matches: {k_prime_computed == rust_k_prime}')

print()

# Now let's trace through the Ed25519 signature algorithm with blinded keys
# Ed25519 signature: (R, s) where:
#   r = SHA512(k' || message)[:64] reduced mod L  (nonce)
#   R = r * B (point on curve)
#   h = SHA512(R || A || message)[:64] reduced mod L
#   s = (r + h * a) mod L

blinded_pubkey = bytes.fromhex('e22bd88bcff2e955c20849244ec82899dbdddda778ba55fa12d0180be5b8e2b5')
blinded_scalar = bytes.fromhex('1038ed706b076e00913258e005263fdf8be4e3dc4c682b59aa86eb8f04aef203')

# For the descriptor signature, what is being signed?
# It's the descriptor content with prefix "Tor onion service descriptor sig v3"
# We don't have the exact message, but we can verify r derivation

# Rust shows r_hash (full 64-byte SHA512 output)
rust_r_hash = bytes.fromhex('5eabd5bc41c9d78ca4adfc143a83b0d315f974d56426c73fa5544a92fba09bc396dfbb756bbf636d434c0b9a614c74a8416d4956a9254efae3c21cb663761e36')
print(f'r_hash from Rust: {rust_r_hash.hex()}')
print(f'r_hash length: {len(rust_r_hash)} bytes')

# r is the first 64 bytes of r_hash interpreted as a scalar mod L
r_int = int.from_bytes(rust_r_hash, 'little') % L
r_computed = int_to_bytes32(r_int)
rust_r = bytes.fromhex('08a15b890e27ed842de12c1bd06b8caa5a9f7989c5b46c60e1dbd0ea9cd8910a')
print(f'r computed (mod L): {r_computed.hex()}')
print(f'r from Rust: {rust_r.hex()}')
print(f'r matches: {r_computed == rust_r}')

print()

# Verify R = r * B
# We can't easily verify this in Python without a full Ed25519 implementation
# But we can verify if R is in the correct format (32 bytes, compressed point)
rust_R = bytes.fromhex('eddb3684db72a89927db18db9c1e1717d1954ead33406688cdcd64249eaf4395')
print(f'R from Rust: {rust_R.hex()}')
print(f'R length: {len(rust_R)} bytes')

# Check if R looks like a valid compressed point
# Last byte should have bit 7 clear for positive Y coordinate
print(f'R last byte: {hex(rust_R[31])}')

print()

# Verify s = (r + h * a) mod L
# We need h = SHA512(R || A || message) to verify this
# Without the message we can only check the math

rust_s = bytes.fromhex('339fe24d0f3820ecaefcf6c620d0c4e9363fd8004e97b6c75aa840d62fdde10c')
print(f's from Rust: {rust_s.hex()}')
s_int = bytes_to_int(rust_s)
a_int = bytes_to_int(blinded_scalar)
r_int_val = bytes_to_int(rust_r)

print(f'\nChecking scalar values are in valid range:')
print(f'r < L: {r_int_val < L}')
print(f'a < L: {a_int < L}')
print(f's < L: {s_int < L}')

# Check the certificate signature format
cert_sig = bytes.fromhex('eddb3684db72a89927db18db9c1e1717d1954ead33406688cdcd64249eaf4395339fe24d0f3820ecaefcf6c620d0c4e9363fd8004e97b6c75aa840d62fdde10c')
print(f'\nFull 64-byte signature:')
print(f'R || s = {cert_sig.hex()}')
print(f'First 32 (R): {cert_sig[:32].hex()}')
print(f'Last 32 (s): {cert_sig[32:].hex()}')
print(f'R matches: {cert_sig[:32] == rust_R}')
print(f's matches: {cert_sig[32:] == rust_s}')

print('\n=== CHECKING STEM SIGNATURE ALGORITHM ===')
# stem's sign_with_blinded_key:
#   r = int.from_bytes(sha512(k_prime + msg), 'little') % l
#   R = (r * B).encode()  # r*B gives a point, encode to 32 bytes
#   h = int.from_bytes(sha512(R + A + msg), 'little') % l
#   s = (r + h * a) % l
#   return R + s.to_bytes(32, 'little')
print('Stem algorithm:')
print('  r = SHA512(k_prime || msg) mod L')
print('  R = r * B  (point multiplication)')
print('  h = SHA512(R || A || msg) mod L')
print('  s = (r + h * a) mod L')
print('  signature = R || s')
print()

# The question is: what is the message being signed?
# For the descriptor signing key cert, it should sign:
#   - cert_version (1 byte)
#   - cert_type (1 byte)  
#   - expiration (4 bytes)
#   - key_type (1 byte)
#   - certified_key (32 bytes)
#   - n_extensions (1 byte)
#   - extension data
# Total certified portion is cert[:-64]

print('The issue might be:')
print('1. Wrong message being signed')
print('2. Wrong prefix for the message') 
print('3. Wrong derivation of k_prime')
print()

# Let's specifically check what stem does for k' derivation
# In stem/descriptor/hidden_service.py, _blinded_sign():
#   k = _blinding_nonce(identity_key, blinding_nonce)  # This is the PRF secret!
#   # Actually no, stem uses different terminology

# Let me trace through stem more carefully
# In stem, the blinded signing looks for the expanded secret key
# which has: secret_scalar (32 bytes) || nonce_seed (32 bytes)
# The nonce_seed is used instead of hash_prefix

print('For expanded Ed25519 keys:')
print('  expanded_secret = secret_scalar (32) || nonce_seed (32)')
print('  When signing: r = SHA512(nonce_seed || msg) mod L')
print()
print(f'RustBalance prf_secret: {prf_secret.hex()}')
print('This should be used to derive k_prime, then r = SHA512(k_prime || msg)')
