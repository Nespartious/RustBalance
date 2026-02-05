#!/usr/bin/env python3
import hashlib

# What OnionBalance uses:
ED25519_BASEPOINT = b"(15112221349535400772501151409588531511" \
        b"454012693041857206046113283949847762202, " \
        b"463168356949264781694283940034751631413" \
        b"07993866256225615783033603165251855960)"

BLIND_STRING = b"Derive temporary signing key" + bytes([0])

identity_pubkey = bytes.fromhex('3bc09efcda967b643680765ff24c16b13a989ebc2a5bf9ff3a68b8db5142be71')
time_period_number = 20487
period_length = 1440  # minutes

N = b"key-blind" + time_period_number.to_bytes(8, 'big') + period_length.to_bytes(8, 'big')

print("=== OnionBalance inputs ===")
print(f"BLIND_STRING ({len(BLIND_STRING)} bytes): {BLIND_STRING.hex()}")
print(f"identity_pubkey ({len(identity_pubkey)} bytes): {identity_pubkey.hex()}")
print(f"ED25519_BASEPOINT ({len(ED25519_BASEPOINT)} bytes): {ED25519_BASEPOINT.hex()}")
print(f"N ({len(N)} bytes): {N.hex()}")

blinding_param = hashlib.sha3_256(BLIND_STRING + identity_pubkey + ED25519_BASEPOINT + N).digest()
print(f"blinding_param: {blinding_param.hex()}")

# Now what RustBalance debug output showed
# Note: RustBalance passes time_period as seconds, then divides by period_len (86400) to get period_num
# And uses period_length_minutes for N construction
rust_time_period = 1770076800  # This is what was passed to blind_identity
rust_period_len = 86400  # seconds
rust_period_num = rust_time_period // rust_period_len  # = 20487 - matches!

# But what does RustBalance compute for N?
# Looking at our code: period_num.to_be_bytes() and period_length_minutes.to_be_bytes()
# Let's see what RustBalance SHOULD use:
print()
print("=== What RustBalance SHOULD compute ===")
print(f"period_num: {rust_period_num}")
print(f"period_length_minutes: 1440")

# The debug output showed:
# time_period=1770076800, period_len=86400, period_len_min=1440, period_num=20487
# blinding_hash=aa8714232ae4e557445d19d02ffbf60609a967592b61de473ddccb11aed94887

# Let's check if RustBalance is computing the hash differently
# Our code: hasher.update(period_num.to_be_bytes()); hasher.update(period_length_minutes.to_be_bytes());
# OnionBalance: N = b"key-blind" + time_period_number.to_bytes(8, 'big') + period_length.to_bytes(8, 'big')

# They should match. Let's verify the N construction:
N_rust = b"key-blind" + (20487).to_bytes(8, 'big') + (1440).to_bytes(8, 'big')
print(f"N_rust should be: {N_rust.hex()}")
print(f"N_onionbalance is: {N.hex()}")
print(f"Match: {N_rust == N}")
