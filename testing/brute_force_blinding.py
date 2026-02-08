#!/usr/bin/env python3
"""Brute force: compute blinding for many time periods to find which one matches Tor's."""
import hashlib
import struct
import time
import ctypes
import ctypes.util

def compute_blinding_factor(pubkey_bytes, period_num, period_length_minutes=1440):
    h = hashlib.sha3_256()
    h.update(b"Derive temporary signing key\x00")
    h.update(pubkey_bytes)
    basepoint = b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"
    h.update(basepoint)
    h.update(b"key-blind")
    h.update(struct.pack(">Q", period_num))
    h.update(struct.pack(">Q", period_length_minutes))
    return h.digest()

def clamp(h):
    b = bytearray(h)
    b[0] &= 248
    b[31] &= 63
    b[31] |= 64
    return bytes(b)

# Load libsodium
lib = ctypes.util.find_library('sodium')
sodium = ctypes.cdll.LoadLibrary(lib)
scalarmult = sodium.crypto_scalarmult_ed25519_noclamp

def blind_pubkey(pubkey_bytes, scalar_bytes):
    result = ctypes.create_string_buffer(32)
    s = ctypes.create_string_buffer(scalar_bytes)
    p = ctypes.create_string_buffer(pubkey_bytes)
    ret = scalarmult(result, s, p)
    if ret != 0:
        return None
    return bytes(result)

pubkey_hex = "ffb71d98e2be36bf10b720281d1b32105202cf70f69af6c128c402783721de08"
pubkey_bytes = bytes.fromhex(pubkey_hex)
tor_blinded = "8902a31a4c05b175facc271b81fc08cec0f16a4a03b2d6b9422b58b99fa0414a"

now = int(time.time())
current_tp = (now // 60 - 720) // 1440
print(f"Current time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(now))}")
print(f"Current TP: {current_tp}")
print(f"Tor's blinded key: {tor_blinded}")
print()

# Try many periods around the current one
print("=== Scanning time periods ===")
for tp in range(current_tp - 5, current_tp + 5):
    h = compute_blinding_factor(pubkey_bytes, tp, 1440)
    c = clamp(h)
    blinded = blind_pubkey(pubkey_bytes, c)
    if blinded:
        match = "*** MATCH ***" if blinded.hex() == tor_blinded else ""
        if match or tp in [current_tp, current_tp + 1]:
            print(f"  TP {tp}: {blinded.hex()} {match}")

# Also try with different period lengths (in case consensus overrides)
print("\n=== Trying different period lengths for TP {current_tp} ===")
for pl in [1440, 720, 360, 180, 60, 1, 86400]:
    h = compute_blinding_factor(pubkey_bytes, current_tp, pl)
    c = clamp(h)
    blinded = blind_pubkey(pubkey_bytes, c)
    if blinded:
        match = "*** MATCH ***" if blinded.hex() == tor_blinded else ""
        print(f"  period_len={pl}: {blinded.hex()} {match}")

# Try using the raw SHA3-256 output (unclamped) as the scalar via crypto_scalarmult_ed25519
# (which does its own clamping)
print("\n=== Trying with libsodium's clamping (crypto_scalarmult_ed25519) ===")
try:
    scalarmult_clamped = sodium.crypto_scalarmult_ed25519
    h = compute_blinding_factor(pubkey_bytes, current_tp, 1440)
    result = ctypes.create_string_buffer(32)
    s = ctypes.create_string_buffer(h)  # RAW hash, not clamped
    p = ctypes.create_string_buffer(pubkey_bytes)
    ret = scalarmult_clamped(result, s, p)
    if ret == 0:
        blinded = bytes(result)
        match = "*** MATCH ***" if blinded.hex() == tor_blinded else ""
        print(f"  With auto-clamp: {blinded.hex()} {match}")
except Exception as e:
    print(f"  Error: {e}")

# Try using the hash as param to stem's _blinded_pubkey
print("\n=== Using stem _blinded_pubkey ===")
try:
    from stem.descriptor.hidden_service import _blinded_pubkey
    import stem.util
    
    for tp in [current_tp, current_tp + 1, current_tp - 1]:
        h = compute_blinding_factor(pubkey_bytes, tp, 1440)
        try:
            blinded = _blinded_pubkey(pubkey_bytes, h)
            match = "*** MATCH ***" if blinded.hex() == tor_blinded else ""
            print(f"  TP {tp}: {blinded.hex() if isinstance(blinded, bytes) else blinded} {match}")
        except Exception as e:
            print(f"  TP {tp}: Error - {e}")
except ImportError as e:
    print(f"  stem not available: {e}")

# Now try: what if we DON'T include the null terminator in BLIND_STRING?
print("\n=== Testing without null terminator in BLIND_STRING ===")
for tp in [current_tp, current_tp + 1]:
    h = hashlib.sha3_256()
    h.update(b"Derive temporary signing key")  # NO null terminator
    h.update(pubkey_bytes)
    basepoint = b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"
    h.update(basepoint)
    h.update(b"key-blind")
    h.update(struct.pack(">Q", tp))
    h.update(struct.pack(">Q", 1440))
    result = h.digest()
    c = clamp(result)
    blinded = blind_pubkey(pubkey_bytes, c)
    if blinded:
        match = "*** MATCH ***" if blinded.hex() == tor_blinded else ""
        print(f"  TP {tp} (no null): {blinded.hex()} {match}")

# What if we use a DIFFERENT basepoint string format?
# Some implementations might use the compressed hex format
print("\n=== Testing with different basepoint formats ===")
for tp in [current_tp]:
    for bp_desc, bp in [
        ("empty", b""),
        ("hex_compressed", b"5866666666666666666666666666666666666666666666666666666666666666"),
    ]:
        h = hashlib.sha3_256()
        h.update(b"Derive temporary signing key\x00")
        h.update(pubkey_bytes)
        h.update(bp)
        h.update(b"key-blind")
        h.update(struct.pack(">Q", tp))
        h.update(struct.pack(">Q", 1440))
        result = h.digest()
        c = clamp(result)
        blinded = blind_pubkey(pubkey_bytes, c)
        if blinded:
            match = "*** MATCH ***" if blinded.hex() == tor_blinded else ""
            print(f"  TP {tp} basepoint={bp_desc}: {blinded.hex()} {match}")
