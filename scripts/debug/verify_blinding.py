#!/usr/bin/env python3
"""Verify blinding computation - compare RustBalance vs stem/OnionBalance"""

# Values from RustBalance debug output:
# Blinding hash (before clamp): ca0438956d09f5b2ee21be7a1d2acca0dafad7b83adacabe47d49d3c72ae5853
# After clamping: c80438956d09f5b2ee21be7a1d2acca0dafad7b83adacabe47d49d3c72ae5853
# blinding_factor_scalar (Rust): 27e16ac4e91999fabe11e84bc4487138dafad7b83adacabe47d49d3c72ae5803
# private_scalar (from secret key): 7daea58365ac4abfa99fdfad0801846bf23c62242940a0bc7b55ecc30b3df90b
# blinded_scalar (Rust): 1038ed706b076e00913258e005263fdf8be4e3dc4c682b59aa86eb8f04aef203
# Blinded pubkey: e22bd88bcff2e955c20849244ec82899dbdddda778ba55fa12d0180be5b8e2b5

# Compare with stem/OnionBalance approach
# In stem: blinding factor = clamp_integer(h) as integer
# Then: blinded_scalar = (blinding_factor * private_scalar) mod l
# Where l = 2^252 + 27742317777372353535851937790883648493

L = 2**252 + 27742317777372353535851937790883648493

# Python: integers are little-endian in byte arrays for Ed25519
def bytes_to_int(b):
    return int.from_bytes(b, 'little')

def int_to_bytes32(n):
    return (n % L).to_bytes(32, 'little')

# The raw blinding hash
h_raw = bytes.fromhex('ca0438956d09f5b2ee21be7a1d2acca0dafad7b83adacabe47d49d3c72ae5853')
print(f'Raw blinding hash h: {h_raw.hex()}')

# Clamping in Python (from stem)
def clamp(h):
    h_list = list(h)
    h_list[0] &= 248  # Clear bits 0,1,2
    h_list[31] &= 63  # Clear bits 254,255 (bits 6,7 of last byte)
    h_list[31] |= 64  # Set bit 254 (bit 6 of last byte)
    return bytes(h_list)

h_clamped = clamp(h_raw)
print(f'Clamped blinding factor: {h_clamped.hex()}')

# The Rust clamped value
rust_clamped = bytes.fromhex('c80438956d09f5b2ee21be7a1d2acca0dafad7b83adacabe47d49d3c72ae5853')
print(f'Rust clamped:           {rust_clamped.hex()}')
print(f'Clamped values match: {h_clamped == rust_clamped}')

# Convert clamped to integer (this is how stem does it)
bf_int = bytes_to_int(h_clamped)
print(f'Blinding factor as integer: {hex(bf_int)}')

# Rust Scalar::from_bytes_mod_order(clamped):
rust_bf_scalar = bytes.fromhex('27e16ac4e91999fabe11e84bc4487138dafad7b83adacabe47d49d3c72ae5803')
rust_bf_int = bytes_to_int(rust_bf_scalar)
print(f'Rust bf_scalar as bytes: {rust_bf_scalar.hex()}')
print(f'Rust bf_scalar as int: {hex(rust_bf_int)}')

# Check if Rust's from_bytes_mod_order reduced it
# Clamped has bit 254 set, which is > L (L is about 2^252)
print(f'\nBit 254 of clamped is set: {(bf_int >> 254) & 1}')
print(f'bf_int > L: {bf_int > L}')

# What value should it be if we DON'T reduce mod L first?
bf_mod_l = bf_int % L
print(f'bf_int mod L: {hex(bf_mod_l)}')
print(f'bf_mod_l as bytes: {int_to_bytes32(bf_mod_l).hex()}')
print(f'This matches Rust bf_scalar: {int_to_bytes32(bf_mod_l) == rust_bf_scalar}')

# Now check the multiplication
private_scalar = bytes.fromhex('7daea58365ac4abfa99fdfad0801846bf23c62242940a0bc7b55ecc30b3df90b')
private_int = bytes_to_int(private_scalar)
print(f'\nPrivate scalar: {private_scalar.hex()}')
print(f'Private scalar as int: {hex(private_int)}')

# Rust's blinded_scalar
rust_blinded = bytes.fromhex('1038ed706b076e00913258e005263fdf8be4e3dc4c682b59aa86eb8f04aef203')
rust_blinded_int = bytes_to_int(rust_blinded)
print(f'Rust blinded_scalar: {rust_blinded.hex()}')

# What Rust computed: (bf_mod_l * private_int) mod L
rust_way = (rust_bf_int * private_int) % L
print(f'\nRust way: (bf_mod_l * a) mod L = {int_to_bytes32(rust_way).hex()}')
print(f'Matches Rust blinded_scalar: {int_to_bytes32(rust_way) == rust_blinded}')

# What stem computes: (bf_int * private_int) mod L (using full clamped value BEFORE mod L)
stem_way = (bf_int * private_int) % L
print(f'Stem way: (bf_int * a) mod L = {int_to_bytes32(stem_way).hex()}')

print(f'\nRust way == Stem way: {rust_way == stem_way}')
print(f'DIFFERENCE: {(rust_way - stem_way) % L}')

# The correct blinded scalar should derive the correct blinded public key
# Let's verify by computing B * blinded_scalar
# Note: we can't easily compute this in Python without a proper Ed25519 library
# But we can at least check if the multiplication is different
print(f'\n=== KEY INSIGHT ===')
print(f'When Rust does from_bytes_mod_order(clamped), it reduces {hex(bf_int)}')
print(f'to {hex(bf_mod_l)} BEFORE multiplication.')
print(f'This changes the result of (blinding_factor * private_scalar) mod L!')
