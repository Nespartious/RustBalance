#!/usr/bin/env python3
"""
Check the blinded key derivation for a master onion address
"""

import hashlib
import time
import struct

# The master onion address (from ob_config)
master_addr = "gc5itylvnbe5x2pbcrwtmsah3hulmpthtwyg3zvbfii4b2kmplgtroad"

# Decode base32 to get identity key
# RFC 4648 base32
def base32_decode(s):
    s = s.upper()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    bits = ""
    for c in s:
        idx = alphabet.index(c)
        bits += format(idx, "05b")
    result = []
    for i in range(0, len(bits) - 7, 8):
        result.append(int(bits[i:i+8], 2))
    return bytes(result)

addr_bytes = base32_decode(master_addr)
print(f"Decoded address bytes ({len(addr_bytes)}): {addr_bytes.hex()}")

# Extract identity key (first 32 bytes)
identity_key = addr_bytes[:32]
checksum = addr_bytes[32:34]
version = addr_bytes[34]

print(f"Identity pubkey: {identity_key.hex()}")
print(f"Checksum: {checksum.hex()}")
print(f"Version: {version}")

# Verify checksum
h = hashlib.sha3_256()
h.update(b".onion checksum")
h.update(identity_key)
h.update(bytes([version]))
expected_checksum = h.digest()[:2]
print(f"Expected checksum: {expected_checksum.hex()}")
print(f"Checksum matches: {checksum == expected_checksum}")

# Now compute the time period and blinding factor
TIME_PERIOD_LENGTH_MINUTES = 1440
TIME_PERIOD_ROTATION_OFFSET_MINUTES = 720

now = int(time.time())
minutes_since_epoch = now // 60
offset_minutes = minutes_since_epoch - TIME_PERIOD_ROTATION_OFFSET_MINUTES
period_num = offset_minutes // TIME_PERIOD_LENGTH_MINUTES

print(f"\nTime period calculation:")
print(f"  Current time (seconds): {now}")
print(f"  Minutes since epoch: {minutes_since_epoch}")
print(f"  After rotation offset: {offset_minutes}")
print(f"  Period number: {period_num}")

# Ed25519 basepoint string as specified in Tor spec
ED25519_BASEPOINT_STR = b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"

# Compute blinding factor
# h = SHA3-256(BLIND_STRING | A | s | B | N)
def compute_blinding_factor(pubkey, period_num, period_len_minutes):
    hasher = hashlib.sha3_256()
    # BLIND_STRING with null terminator
    hasher.update(b"Derive temporary signing key\x00")
    # A = 32-byte public identity key
    hasher.update(pubkey)
    # s = shared secret (empty for standard blinding)
    # B = Ed25519 basepoint string representation
    hasher.update(ED25519_BASEPOINT_STR)
    # N = "key-blind" + period_num + period_length
    hasher.update(b"key-blind")
    hasher.update(struct.pack(">Q", period_num))  # big-endian u64
    hasher.update(struct.pack(">Q", period_len_minutes))  # big-endian u64
    return hasher.digest()

blinding_factor = compute_blinding_factor(identity_key, period_num, TIME_PERIOD_LENGTH_MINUTES)
print(f"\nBlinding factor (raw): {blinding_factor.hex()}")

# Clamp for Ed25519 scalar
def clamp_integer(h):
    h = bytearray(h)
    h[0] &= 248
    h[31] &= 63
    h[31] |= 64
    return bytes(h)

clamped = clamp_integer(blinding_factor)
print(f"Blinding factor (clamped): {clamped.hex()}")

# Now we need to do the scalar multiplication A' = h * A
# This requires curve25519 operations
try:
    import nacl.bindings
    
    # Convert blinding factor to scalar (little-endian)
    # Note: curve25519-dalek uses little-endian, but Tor spec uses network byte order
    # The Scalar::from_bytes_mod_order takes bytes in little-endian
    
    # We need to decompress the public key to an Ed25519 point and multiply by scalar
    # This is complex - let me try to compute what Tor would compute
    
    # For now, just show the inputs that RustBalance should be using
    print(f"\n=== Expected inputs for blinding ===")
    print(f"Public key: {identity_key.hex()}")
    print(f"Period num: {period_num}")
    print(f"Period len minutes: {TIME_PERIOD_LENGTH_MINUTES}")
    print(f"Blinding factor (clamped): {clamped.hex()}")
    
except ImportError:
    print("pynacl not available for scalar multiplication")

# Also compute subcredential for reference
# credential = H("credential" || public_key)
cred_hasher = hashlib.sha3_256()
cred_hasher.update(b"credential")
cred_hasher.update(identity_key)
credential = cred_hasher.digest()
print(f"\nCredential: {credential.hex()}")
