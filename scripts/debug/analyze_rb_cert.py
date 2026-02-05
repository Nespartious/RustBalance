#!/usr/bin/env python3
"""
Analyze the descriptor-signing-key-cert from RustBalance's output
"""

import base64
import struct

# The cert from RustBalance's log
cert_hex = "0108000780c001e1c736f5929b3d495d980d2d4edb456dc9fb956feda522e87939ccce74528ad60100200401e22bd88bcff2e955c20849244ec82899dbdddda778ba55fa12d0180be5b8e2b519cac6b102b6f07d818142c8d1bd06214c82f9aaac5a339748624841a75be615ed060183ae0c45fcf2c9a4991ae8d017a66c25e2c436f0a30763fd3eb2e79b08"

cert = bytes.fromhex(cert_hex)
print(f"Certificate length: {len(cert)} bytes")
print(f"Certificate hex: {cert.hex()}")

# Parse according to Tor cert-spec.txt
pos = 0

# Version (1 byte)
version = cert[pos]
pos += 1
print(f"\n[0] Version: {version} (expected: 1)")

# Cert type (1 byte)
cert_type = cert[pos]
pos += 1
print(f"[1] Cert type: {cert_type} (expected: 8)")

# Expiration (4 bytes, hours since epoch)
expiry = struct.unpack(">I", cert[pos:pos+4])[0]
pos += 4
import datetime
expiry_dt = datetime.datetime.utcfromtimestamp(expiry * 3600)
print(f"[2-5] Expiration (hours since epoch): {expiry} = {expiry_dt}")

# Cert key type (1 byte)
key_type = cert[pos]
pos += 1
print(f"[6] Cert key type: {key_type} (expected: 1 = Ed25519)")

# Certified key (32 bytes) - this is the descriptor signing public key
certified_key = cert[pos:pos+32]
pos += 32
print(f"[7-38] Certified key (desc signing key): {certified_key.hex()}")

# Number of extensions (1 byte)
n_ext = cert[pos]
pos += 1
print(f"[39] Number of extensions: {n_ext}")

# Parse extensions
for i in range(n_ext):
    ext_len = struct.unpack(">H", cert[pos:pos+2])[0]
    pos += 2
    ext_type = cert[pos]
    pos += 1
    ext_flags = cert[pos]
    pos += 1
    ext_data = cert[pos:pos+ext_len]
    pos += ext_len
    
    print(f"\n  Extension {i}:")
    print(f"    Length: {ext_len}")
    print(f"    Type: {ext_type} (expected: 4 = signed-with-ed25519-key)")
    print(f"    Flags: {ext_flags} (expected: 1 = AFFECTS_VALIDATION)")
    print(f"    Data: {ext_data.hex()}")
    
    if ext_type == 4:
        print(f"    -> This is the BLINDED public key")

# Signature (remaining 64 bytes)
signature = cert[pos:]
print(f"\n[{pos}-end] Signature ({len(signature)} bytes): {signature.hex()}")

# Data that was signed (everything before signature)
signed_data = cert[:pos]
print(f"\nData that was signed: {len(signed_data)} bytes")
print(f"Signed data hex: {signed_data.hex()}")

# Extract blinded key from extension
ext_pos = 40  # After n_ext byte
ext_len = struct.unpack(">H", cert[ext_pos:ext_pos+2])[0]
ext_type = cert[ext_pos+2]
ext_flags = cert[ext_pos+3]
blinded_pubkey = cert[ext_pos+4:ext_pos+4+ext_len]

print(f"\nBlinded public key from cert: {blinded_pubkey.hex()}")

# Expected blinded key from our computation
expected_blinded = "e22bd88bcff2e955c20849244ec82899dbdddda778ba55fa12d0180be5b8e2b5"
print(f"Expected blinded key:         {expected_blinded}")
print(f"Match: {blinded_pubkey.hex() == expected_blinded}")

# Verify signature using ed25519
try:
    from nacl.signing import VerifyKey
    
    vk = VerifyKey(blinded_pubkey)
    
    # For ed25519 verification, we need signature + message
    # nacl.signing expects the signature to come first
    try:
        vk.verify(signature + signed_data)
        print("\n✓ Signature verification PASSED")
    except Exception as e:
        print(f"\n✗ Signature verification FAILED: {e}")
        
        # Try with just the signature bytes as Ed25519 signature
        try:
            import nacl.bindings
            result = nacl.bindings.crypto_sign_open(signature + signed_data, blinded_pubkey)
            print(f"crypto_sign_open succeeded: {result.hex()}")
        except Exception as e2:
            print(f"crypto_sign_open also failed: {e2}")
        
except ImportError:
    print("\nCannot verify signature without PyNaCl")

# Also show the base64 encoding for comparison with what Tor sees
print(f"\nBase64 of full cert: {base64.b64encode(cert).decode()}")
