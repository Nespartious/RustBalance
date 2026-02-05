#!/usr/bin/env python3
import hashlib

h = bytes.fromhex("aa8714232ae4e557445d19d02ffbf60609a967592b61de473ddccb11aed94887")
h_list = list(h)

print(f"Original h: {h.hex()}")
print(f"h[0] = 0x{h[0]:02x} = {h[0]:08b}")
print(f"h[31] = 0x{h[31]:02x} = {h[31]:08b}")

# RustBalance clamping
h_rust = list(h)
h_rust[0] = h_rust[0] & 248
h_rust[31] = h_rust[31] & 63
h_rust[31] = h_rust[31] | 64
print(f"\nRustBalance clamped: {bytes(h_rust).hex()}")
print(f"h_rust[31] = 0x{h_rust[31]:02x} = {h_rust[31]:08b}")

# Tor spec clamping  
h_tor = list(h)
h_tor[0] = h_tor[0] & 248
h_tor[31] = h_tor[31] & 127
h_tor[31] = h_tor[31] | 64
print(f"\nTor spec clamped:   {bytes(h_tor).hex()}")
print(f"h_tor[31] = 0x{h_tor[31]:02x} = {h_tor[31]:08b}")

print(f"\nMatch: {h_rust == h_tor}")

# Now compute the actual clamped blinding factor using Stem's approach
# mult = 2 ** (b - 2) + sum(2 ** i * bit(h, i) for i in range(3, b - 2))
# where b = 256
b = 256

def bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1

mult = 2 ** (b - 2)
for i in range(3, b - 2):
    mult += 2 ** i * bit(h, i)

print(f"\nStem/OnionBalance mult = {mult}")
print(f"As bytes: {mult.to_bytes(32, 'little').hex()}")
