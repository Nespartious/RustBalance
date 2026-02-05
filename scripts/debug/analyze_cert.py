#!/usr/bin/env python3
"""
Analyze the descriptor-signing-key-cert from a v3 onion descriptor
"""

import base64
import struct

# The cert from the cached descriptor
cert_b64 = """AQgAB4DzAT9lG6GLgR5DlQ++a+55T2qXAsFtMNBijqaNZ52ZwySlAQAgBADiK9iL
z/LpVcIISSROyCiZ293dp3i6VfoS0BgL5bjitX3g1zu5Hcbh/7TYwF5q4V7DWFWP
q8ilF7v8GZNGaz24IZ8H7wpm/x+3I/YPSlSzcZQNq4DBorfw9+y4ri9/3gw="""

cert = base64.b64decode(cert_b64.replace("\n", ""))
print(f"Certificate length: {len(cert)} bytes")
print(f"Certificate hex: {cert.hex()}")

# Parse according to Tor cert-spec.txt
# https://spec.torproject.org/cert-spec

pos = 0

# Version (1 byte)
version = cert[pos]
pos += 1
print(f"\n[0] Version: {version} (expected: 1)")

# Cert type (1 byte)
cert_type = cert[pos]
pos += 1
print(f"[1] Cert type: {cert_type} (expected: 8 = SIGNING_KEY_V_BLINDED_ED25519)")
# Note: Type 8 = The signing key is certified by a blinded identity key
# But wait - for OnionBalance, we need type 8 which says the SIGNING KEY
# (the descriptor signing key) is certified BY the BLINDED identity key

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
    print(f"    Type: {ext_type}")
    print(f"    Flags: {ext_flags}")
    print(f"    Data: {ext_data.hex()}")
    
    if ext_type == 4:
        print(f"    -> Type 4 = signed-with-ed25519-key")
        print(f"    -> This is the BLINDED public key")

# Signature (remaining 64 bytes)
signature = cert[pos:]
print(f"\n[{pos}-end] Signature ({len(signature)} bytes): {signature.hex()}")

# Now verify the signature
# The signature covers everything before it (cert[0:pos])
signed_data = cert[:pos]
print(f"\nData to verify: {len(signed_data)} bytes")

# For verification, we need the blinded public key (from extension 4)
# Let me re-extract it
pos = 40  # After certified key
n_ext = cert[39]
for i in range(n_ext):
    ext_len = struct.unpack(">H", cert[pos:pos+2])[0]
    ext_type = cert[pos+2]
    ext_flags = cert[pos+3]
    ext_data = cert[pos+4:pos+4+ext_len]
    pos += 4 + ext_len
    
    if ext_type == 4:
        blinded_pubkey = ext_data
        break

print(f"\nBlinded public key from cert: {blinded_pubkey.hex()}")

# Expected blinded key from our computation
expected_blinded = "e22bd88bcff2e955c20849244ec82899dbdddda778ba55fa12d0180be5b8e2b5"
print(f"Expected blinded key:         {expected_blinded}")
print(f"Match: {blinded_pubkey.hex() == expected_blinded}")

# Verify signature using ed25519
try:
    from nacl.signing import VerifyKey
    
    vk = VerifyKey(blinded_pubkey)
    
    # The signature is over just the certificate prefix (without the signature itself)
    try:
        vk.verify(signature + signed_data)  # nacl expects signature first
        print("\n✓ Signature verification PASSED")
    except Exception as e:
        print(f"\n✗ Signature verification FAILED: {e}")
        
except ImportError:
    print("\nCannot verify signature without PyNaCl")
