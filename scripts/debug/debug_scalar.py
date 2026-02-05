#!/usr/bin/env python3

# The clamped blinding factor
clamped = bytes.fromhex("a88714232ae4e557445d19d02ffbf60609a967592b61de473ddccb11aed94847")
clamped_int = int.from_bytes(clamped, 'little')

# Ed25519 group order
l = 2**252 + 27742317777372353535851937790883648493

print(f"Clamped as integer: {clamped_int}")
print(f"Ed25519 order l:    {l}")
print(f"clamped < l:        {clamped_int < l}")
print(f"clamped mod l:      {clamped_int % l}")

# If clamped >= l, then from_bytes_mod_order would reduce it
if clamped_int >= l:
    reduced = clamped_int % l
    reduced_bytes = reduced.to_bytes(32, 'little')
    print(f"Reduced to:         {reduced_bytes.hex()}")
else:
    print("No reduction needed - clamped is already < l")

# Now compute the blinded public key using PyNaCl
from nacl.bindings import crypto_scalarmult_ed25519_noclamp, crypto_core_ed25519_is_valid_point

# Master public key
pubkey = bytes.fromhex("3bc09efcda967b643680765ff24c16b13a989ebc2a5bf9ff3a68b8db5142be71")

# The clamped scalar is already in the right format
# PyNaCl's crypto_scalarmult_ed25519_noclamp expects:
# - scalar: 32 bytes (little-endian)
# - point: 32 bytes (compressed Edwards Y)

try:
    blinded = crypto_scalarmult_ed25519_noclamp(clamped, pubkey)
    print(f"\nBlinded pubkey:     {blinded.hex()}")
except Exception as e:
    print(f"Error: {e}")
    
# Also try the clamped version
from nacl.bindings import crypto_scalarmult_ed25519

try:
    blinded_clamped = crypto_scalarmult_ed25519(clamped, pubkey)
    print(f"Blinded (clamped):  {blinded_clamped.hex()}")
except Exception as e:
    print(f"Error with clamped: {e}")
