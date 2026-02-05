#!/usr/bin/env python3
"""
Compute the blinded public key for a v3 onion service
using the exact Tor algorithm.
"""
import hashlib
import struct
import time

# Try to use nacl for EC operations
try:
    from nacl.bindings import crypto_scalarmult_ed25519_noclamp
    from nacl.bindings import crypto_core_ed25519_scalar_mul
    HAS_NACL = True
except ImportError:
    HAS_NACL = False
    print("Warning: nacl not available for EC operations")

def clamp_scalar(h):
    """Clamp a 32-byte value for use as Ed25519 scalar"""
    h = bytearray(h)
    h[0] &= 248
    h[31] &= 63
    h[31] |= 64
    return bytes(h)

def compute_blinding_param(pubkey, period_num, period_length):
    """
    Compute the blinding parameter h using Tor's algorithm.
    h = SHA3-256(BLIND_STRING | pubkey | ed25519-basepoint | nonce)
    """
    blind_str = b"Derive temporary signing key\x00"
    basepoint = b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"
    
    # Build nonce: "key-blind" || period_num || period_length (both big-endian u64)
    nonce = b"key-blind" + struct.pack(">Q", period_num) + struct.pack(">Q", period_length)
    
    h = hashlib.sha3_256()
    h.update(blind_str)
    h.update(pubkey)
    h.update(basepoint)
    h.update(nonce)
    
    return h.digest()

def get_tor_period_num(now=None):
    """Calculate Tor's time period number"""
    if now is None:
        now = int(time.time())
    minutes_since_epoch = now // 60
    rotation_offset = 12 * 60  # 720 minutes
    minutes_adjusted = minutes_since_epoch - rotation_offset
    period_length = 1440  # minutes
    return minutes_adjusted // period_length

def main():
    # The identity public key
    pubkey_hex = "e33734887a0d09abdf3470ca9839814b5813e29844f05feaff0609899f8ce633"
    pubkey = bytes.fromhex(pubkey_hex)
    
    now = int(time.time())
    period_num = get_tor_period_num(now)
    period_length = 1440  # minutes
    
    print(f"Current Unix time: {now}")
    print(f"Period number: {period_num}")
    print(f"Period length: {period_length} minutes")
    print(f"Identity pubkey: {pubkey_hex}")
    
    # Compute blinding parameter
    h = compute_blinding_param(pubkey, period_num, period_length)
    print(f"\nBlinding param h: {h.hex()}")
    
    # Clamp for scalar usage
    h_clamped = clamp_scalar(h)
    print(f"Clamped h: {h_clamped.hex()}")
    
    # Perform EC scalar multiplication: A' = h * A
    if HAS_NACL:
        try:
            # nacl's crypto_scalarmult_ed25519_noclamp does scalar * point
            blinded = crypto_scalarmult_ed25519_noclamp(h_clamped, pubkey)
            print(f"\nBlinded public key: {blinded.hex()}")
        except Exception as e:
            print(f"EC multiplication failed: {e}")
            # Try alternative approach
            print("\nTrying with ge25519 operations...")
    else:
        print("\nCannot compute EC multiplication without nacl")
    
    # What our Rust code would produce with the same h
    print("\n--- Verification ---")
    print(f"If Rust uses the same h_clamped, the blinded key should match.")

if __name__ == "__main__":
    main()
