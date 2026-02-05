#!/usr/bin/env python3
"""Full MAC verification with detailed debugging."""

import hashlib

# Values from RustBalance debug output
blinded_key = bytes.fromhex('35583b72129f59ed130df845d1b45eabfe9b013817e9fef1d37a9544da1896b0')
subcred = bytes.fromhex('2a90ac1ef4e0687ddb406d9d1829950fe9bdf66779d02fe4f8823f2435588cdc')
revision = 2368585779
salt = bytes.fromhex('be068c0bc631b310a3a57d7754e4579b')
string_constant = b'hsdir-superencrypted-data'

# Read encrypted data
encrypted = open('/tmp/debug_encrypted.bin', 'rb').read()
ciphertext = open('/tmp/debug_ciphertext.bin', 'rb').read()

print("=== INPUT VERIFICATION ===")
print(f"blinded_key:     {blinded_key.hex()}")
print(f"subcred:         {subcred.hex()}")
print(f"revision:        {revision}")
print(f"salt:            {salt.hex()}")
print(f"string_constant: {string_constant}")
print(f"encrypted:       {len(encrypted)} bytes")
print(f"ciphertext:      {len(ciphertext)} bytes")
print()

# Build secret_input
secret_input = blinded_key + subcred + revision.to_bytes(8, 'big')
print("=== SECRET_INPUT ===")
print(f"secret_input ({len(secret_input)} bytes): {secret_input.hex()}")
rb_secret = '35583b72129f59ed130df845d1b45eabfe9b013817e9fef1d37a9544da1896b02a90ac1ef4e0687ddb406d9d1829950fe9bdf66779d02fe4f8823f2435588cdc000000008d2dc033'
print(f"RustBalance:      {rb_secret}")
print(f"Match: {secret_input.hex() == rb_secret}")
print()

# KDF: SHAKE-256(secret_input || salt || string_constant, 80)
xof = hashlib.shake_256()
xof.update(secret_input)
xof.update(salt)
xof.update(string_constant)
kdf_output = xof.digest(80)

secret_key = kdf_output[:32]
secret_iv = kdf_output[32:48]
mac_key = kdf_output[48:80]

print("=== KDF OUTPUT ===")
print(f"SECRET_KEY: {secret_key.hex()}")
print(f"SECRET_IV:  {secret_iv.hex()}")
print(f"MAC_KEY:    {mac_key.hex()}")

rb_mac_key = 'c84b683e234dfb6613eefdba0b349c68402dbc3119d10737d13306623efb1082'
print(f"RB MAC_KEY: {rb_mac_key}")
print(f"Match: {mac_key.hex() == rb_mac_key}")
print()

# MAC: SHA3-256(mac_key_len || MAC_KEY || salt_len || SALT || ENCRYPTED)
mac_key_len = len(mac_key).to_bytes(8, 'big')
salt_len = len(salt).to_bytes(8, 'big')

print("=== MAC COMPUTATION ===")
print(f"mac_key_len (8 BE): {mac_key_len.hex()}")
print(f"salt_len (8 BE):    {salt_len.hex()}")
print(f"encrypted first 16: {encrypted[:16].hex()}")
print(f"encrypted last 16:  {encrypted[-16:].hex()}")

hasher = hashlib.sha3_256()
hasher.update(mac_key_len)
hasher.update(mac_key)
hasher.update(salt_len)
hasher.update(salt)
hasher.update(encrypted)
computed_mac = hasher.digest()

expected_mac = bytes.fromhex('4ce46a481c76cbd893eb6a421ec12f0dae638b9a61060337d582b10532e69d01')

print()
print(f"Expected MAC: {expected_mac.hex()}")
print(f"Computed MAC: {computed_mac.hex()}")
print(f"Match: {computed_mac == expected_mac}")

# If they don't match, the encrypted body we have is wrong,
# OR the blinded key used to encrypt was different
print()
print("=== ANALYSIS ===")
if computed_mac != expected_mac:
    print("MAC does NOT match!")
    print("Possible causes:")
    print("  1. Wrong blinded key (the cert has a different blinded key than was used to encrypt)")
    print("  2. Wrong encrypted body (base64 decode issue)")
    print("  3. Wrong salt (extracted from wrong position)")
    print()
    
    # Verify ciphertext structure
    print("Ciphertext structure check:")
    print(f"  First 16 (salt):     {ciphertext[:16].hex()}")
    print(f"  Salt we're using:    {salt.hex()}")
    print(f"  Match: {ciphertext[:16] == salt}")
    print()
    print(f"  Last 32 (mac):       {ciphertext[-32:].hex()}")
    print(f"  Expected mac:        {expected_mac.hex()}")
    print(f"  Match: {ciphertext[-32:] == expected_mac}")
    print()
    print(f"  Middle (encrypted):  {len(ciphertext) - 48} bytes")
    print(f"  Our encrypted:       {len(encrypted)} bytes")
    print(f"  Match: {len(ciphertext) - 48 == len(encrypted)}")
    print()
    
    # Check if encrypted matches what's in ciphertext
    cipher_encrypted = ciphertext[16:-32]
    print(f"  Encrypted from ciphertext first 16: {cipher_encrypted[:16].hex()}")
    print(f"  Our encrypted first 16:             {encrypted[:16].hex()}")
    print(f"  Match: {cipher_encrypted == encrypted}")
