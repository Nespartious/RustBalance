#!/usr/bin/env python3
"""
Compute the blinded public key for VM2's hidden service identity key
"""
import hashlib
import struct
import time

try:
    from nacl.bindings import crypto_scalarmult_ed25519_noclamp
    HAS_NACL = True
except ImportError:
    HAS_NACL = False

def clamp_scalar(h):
    h = bytearray(h)
    h[0] &= 248
    h[31] &= 63
    h[31] |= 64
    return bytes(h)

def compute_blinding_param(pubkey, period_num, period_length):
    blind_str = b"Derive temporary signing key\x00"
    basepoint = b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"
    nonce = b"key-blind" + struct.pack(">Q", period_num) + struct.pack(">Q", period_length)
    
    h = hashlib.sha3_256()
    h.update(blind_str)
    h.update(pubkey)
    h.update(basepoint)
    h.update(nonce)
    return h.digest()

def get_tor_period_num(now=None):
    if now is None:
        now = int(time.time())
    minutes_since_epoch = now // 60
    rotation_offset = 12 * 60
    minutes_adjusted = minutes_since_epoch - rotation_offset
    period_length = 1440
    return minutes_adjusted // period_length

def main():
    # VM2's identity public key
    pubkey_hex = "b0dcf68c63f4381197763bf6fcefb8631dc65c8cdf4919e013a47db0696219b9"
    pubkey = bytes.fromhex(pubkey_hex)
    
    now = int(time.time())
    period_num = get_tor_period_num(now)
    period_length = 1440
    
    print(f"VM2 Identity pubkey: {pubkey_hex}")
    print(f"Period number: {period_num}")
    
    h = compute_blinding_param(pubkey, period_num, period_length)
    h_clamped = clamp_scalar(h)
    print(f"Blinding param h: {h.hex()}")
    print(f"Clamped h: {h_clamped.hex()}")
    
    if HAS_NACL:
        blinded = crypto_scalarmult_ed25519_noclamp(h_clamped, pubkey)
        print(f"Our computed blinded key: {blinded.hex()}")
    
    # Now let's compare with what Tor published
    # We need to fetch the descriptor and extract the blinded key from it
    print("\nNow compare with Tor's descriptor on this machine...")

if __name__ == "__main__":
    main()
