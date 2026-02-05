#!/usr/bin/env python3
"""
Verify the blinded key computation using PyNaCl/libsodium
"""

import hashlib
import struct

# Install nacl if needed: pip install pynacl

try:
    from nacl._sodium import ffi, lib
    from nacl.signing import SigningKey, VerifyKey
    import nacl.bindings
    HAS_NACL = True
except ImportError:
    HAS_NACL = False
    print("PyNaCl not available - install with: pip install pynacl")

# Identity public key from onion address
identity_key_hex = "30ba89e1756849dbe9e1146d364807d9e8b63e679db06de6a12a11c0e94c7acd"
identity_key = bytes.fromhex(identity_key_hex)

# Time period parameters
TIME_PERIOD_LENGTH_MINUTES = 1440
period_num = 20487

# Ed25519 basepoint string
ED25519_BASEPOINT_STR = b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"

def compute_blinding_factor(pubkey, period_num, period_len_minutes):
    hasher = hashlib.sha3_256()
    hasher.update(b"Derive temporary signing key\x00")
    hasher.update(pubkey)
    hasher.update(ED25519_BASEPOINT_STR)
    hasher.update(b"key-blind")
    hasher.update(struct.pack(">Q", period_num))  # big-endian u64
    hasher.update(struct.pack(">Q", period_len_minutes))  # big-endian u64
    return hasher.digest()

def clamp_integer(h):
    h = bytearray(h)
    h[0] &= 248
    h[31] &= 63
    h[31] |= 64
    return bytes(h)

blinding_factor = compute_blinding_factor(identity_key, period_num, TIME_PERIOD_LENGTH_MINUTES)
clamped = clamp_integer(blinding_factor)

print(f"Identity pubkey: {identity_key.hex()}")
print(f"Period num: {period_num}")
print(f"Blinding factor (raw): {blinding_factor.hex()}")
print(f"Blinding factor (clamped): {clamped.hex()}")

# RustBalance computed blinded key
rustbalance_blinded = "e22bd88bcff2e955c20849244ec82899dbdddda778ba55fa12d0180be5b8e2b5"
print(f"\nRustBalance blinded key: {rustbalance_blinded}")

# Now let's try to compute the blinded key using Ed25519 scalar multiplication
# The blinded public key is: A' = h * A (scalar * point multiplication)

if HAS_NACL:
    # Try using ge25519_scalarmult if available
    # The clamped scalar needs to be treated as little-endian for curve ops
    
    # ed25519 points are stored as compressed Y coordinates
    # To do h * A, we need to:
    # 1. Decompress A to a point
    # 2. Scalar multiply by h
    # 3. Compress back
    
    # Use crypto_scalarmult_ed25519 if available (recent libsodium)
    try:
        # This function computes q = n * p where n is a scalar and p is a point
        blinded = nacl.bindings.crypto_scalarmult_ed25519_noclamp(clamped, identity_key)
        print(f"PyNaCl computed blinded key: {blinded.hex()}")
        print(f"Match: {blinded.hex() == rustbalance_blinded}")
    except Exception as e:
        print(f"crypto_scalarmult_ed25519_noclamp failed: {e}")
        
        # Try alternative approach - use the point as if it were a base
        try:
            # The problem is that Ed25519 point mult isn't always exposed
            # Let's try another way
            print("Trying alternative computation...")
            
            # For reference, we can at least verify the public key is a valid point
            try:
                vk = VerifyKey(identity_key)
                print(f"Identity key is a valid Ed25519 point")
            except Exception as e2:
                print(f"Identity key validation failed: {e2}")
        except Exception as e2:
            print(f"Alternative failed: {e2}")

else:
    print("\nCannot verify scalar multiplication without PyNaCl")
    print("The key question is whether RustBalance's curve25519-dalek computation is correct")

# Let's also try using ed25519-donna or pure python implementation
print("\n=== Trying pure Python Ed25519 computation ===")

# Ed25519 constants
p = 2**255 - 19
d = -121665 * pow(121666, -1, p) % p
q = 2**252 + 27742317777372353535851937790883648493

def from_bytes(b):
    return int.from_bytes(b, 'little')

def to_bytes(n):
    return n.to_bytes(32, 'little')

def modp_inv(a):
    return pow(a, p - 2, p)

def decompress(s):
    """Decompress an Ed25519 point from 32 bytes"""
    y = from_bytes(s) & ((1 << 255) - 1)
    x_sign = s[31] >> 7
    
    # Recover x from y
    # x^2 = (y^2 - 1) / (d*y^2 + 1) mod p
    y2 = y * y % p
    x2 = (y2 - 1) * modp_inv(d * y2 + 1) % p
    
    if x2 == 0:
        if x_sign:
            return None  # Invalid
        return (0, y)
    
    # Modular square root
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * pow(2, (p - 1) // 4, p) % p
    if (x * x - x2) % p != 0:
        return None  # Invalid
    
    if (x & 1) != x_sign:
        x = p - x
    
    return (x, y)

def compress(point):
    """Compress an Ed25519 point to 32 bytes"""
    x, y = point
    result = bytearray(to_bytes(y % p))
    result[31] |= (x & 1) << 7
    return bytes(result)

def point_add(P, Q):
    """Add two Ed25519 points"""
    x1, y1 = P
    x2, y2 = Q
    
    # Extended coordinates addition formula
    x3 = (x1*y2 + x2*y1) * modp_inv(1 + d*x1*x2*y1*y2) % p
    y3 = (y1*y2 + x1*x2) * modp_inv(1 - d*x1*x2*y1*y2) % p
    
    return (x3, y3)

def scalar_mult(s, P):
    """Compute s * P using double-and-add"""
    # s is an integer scalar
    Q = (0, 1)  # Identity point (neutral element)
    
    n = s
    R = P
    
    while n > 0:
        if n & 1:
            Q = point_add(Q, R)
        R = point_add(R, R)
        n >>= 1
    
    return Q

# Decompress the identity key
point = decompress(identity_key)
if point is None:
    print("Failed to decompress identity key")
else:
    print(f"Decompressed point x (first 40 hex): {hex(point[0])[:42]}...")
    print(f"Decompressed point y (first 40 hex): {hex(point[1])[:42]}...")
    
    # Convert clamped scalar to integer (little-endian)
    scalar_int = from_bytes(clamped)
    print(f"Scalar as integer: {hex(scalar_int)}")
    
    # Compute blinded point
    blinded_point = scalar_mult(scalar_int, point)
    blinded_compressed = compress(blinded_point)
    print(f"\nPure Python computed blinded key: {blinded_compressed.hex()}")
    print(f"RustBalance blinded key:          {rustbalance_blinded}")
    print(f"Match: {blinded_compressed.hex() == rustbalance_blinded}")
