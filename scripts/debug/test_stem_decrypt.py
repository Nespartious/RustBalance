#!/usr/bin/env python3
"""
Test script to understand stem's descriptor decryption.
Creates a descriptor, encrypts it, then decrypts to verify our understanding.
"""

import hashlib
import struct
import os

from stem.descriptor.hidden_service import HiddenServiceDescriptorV3

def test_decrypt_known():
    """Test decryption with a descriptor created by stem"""
    
    # Create a test descriptor using stem
    print("Creating test descriptor...")
    
    try:
        desc = HiddenServiceDescriptorV3.create()
        print(f"Created descriptor with onion address prefix")
        
        # The descriptor should have an onion_address method or attribute
        # after creation
        print(f"Descriptor version: {desc.version}")
        print(f"Revision counter: {desc.revision_counter}")
        print(f"Has signing_cert: {desc.signing_cert is not None}")
        
        if desc.signing_cert:
            blinded_key = desc.signing_cert.signing_key()
            if blinded_key:
                print(f"Blinded key from cert (32 bytes): {blinded_key.hex()}")
        
    except Exception as e:
        print(f"Error creating descriptor: {e}")
        import traceback
        traceback.print_exc()

def test_layer_cipher():
    """Test the layer cipher function directly"""
    import hashlib
    import struct
    
    print("\n=== Testing layer cipher construction ===")
    
    # Test with the ACTUAL values from the debug output
    # These are the values RustBalance is using
    blinded_key = bytes.fromhex("35583b72129f59ed130df845d1b45eabfe9b013817e9fef1d37a9544da1896b0")
    subcredential = bytes.fromhex("2a90ac1ef4e0687ddb406d9d1829950fe9bdf66779d02fe4f8823f2435588cdc")
    revision_counter = 1
    # Use actual salt from our descriptor (we'll need to get this)
    salt = bytes.fromhex("afaa405afa64e3bf7e07f1ed74bd46fe")  # actual salt from debug
    
    S_KEY_LEN = 32
    S_IV_LEN = 16
    MAC_LEN = 32
    
    constant_outer = b'hsdir-superencrypted-data'
    
    secret_input = blinded_key + subcredential + struct.pack('>Q', revision_counter) + salt + constant_outer
    print(f"secret_input length: {len(secret_input)}")
    print(f"secret_input: {secret_input.hex()}")
    
    kdf = hashlib.shake_256(secret_input)
    keys = kdf.digest(S_KEY_LEN + S_IV_LEN + MAC_LEN)
    
    s_key = keys[:S_KEY_LEN]
    s_iv = keys[S_KEY_LEN:S_KEY_LEN+S_IV_LEN]
    mac_key = keys[S_KEY_LEN+S_IV_LEN:]
    
    print(f"\nDerived keys (Python):")
    print(f"  s_key (32): {s_key.hex()}")
    print(f"  s_iv (16): {s_iv.hex()}")
    print(f"  mac_key (32): {mac_key.hex()}")
    
    # Compare with RustBalance's derived keys from the debug output:
    # secret_key=9dba55f5..., secret_iv=..., mac_key=...
    # We need to get these values from RustBalance log
    
    print("\nThese should match RustBalance's derived keys.")
    print("If they don't match, the SHAKE-256 input ordering is different.")

def verify_subcredential():
    """Verify subcredential computation matches stem"""
    print("\n=== Verifying subcredential computation ===")
    
    # Our backend onion: esnymppkuwdhwam6vzthfvtl2i2y64rwwyt23gp63xmctndqp5tvgaad.onion
    onion_address = "esnymppkuwdhwam6vzthfvtl2i2y64rwwyt23gp63xmctndqp5tvgaad"
    
    # Decode identity key from onion address
    import base64
    # onion address is 56 chars, base32 encoded 35 bytes (32 pubkey + 2 checksum + 1 version)
    # Pad to multiple of 8
    padded = onion_address.upper()
    # 56 chars needs to be padded to 64 for proper base32
    while len(padded) % 8 != 0:
        padded += "="
    decoded = base64.b32decode(padded)
    identity_key = decoded[:32]
    
    print(f"Identity key: {identity_key.hex()}")
    
    # Our blinded key (from previous extraction)
    blinded_key = bytes.fromhex("35583b72129f59ed130df845d1b45eabfe9b013817e9fef1d37a9544da1896b0")
    
    # Stem's subcredential computation:
    # credential = hashlib.sha3_256(b'credential' + identity_key).digest()
    # subcredential = hashlib.sha3_256(b'subcredential' + credential + blinded_key).digest()
    
    credential = hashlib.sha3_256(b'credential' + identity_key).digest()
    print(f"Credential: {credential.hex()}")
    
    subcredential = hashlib.sha3_256(b'subcredential' + credential + blinded_key).digest()
    print(f"Subcredential: {subcredential.hex()}")
    
    # Compare with what we computed before
    expected = "2a90ac1ef4e0687ddb406d9d1829950fe9bdf66779d02fe4f8823f2435588cdc"
    print(f"Expected:      {expected}")
    print(f"Match: {subcredential.hex() == expected}")

if __name__ == "__main__":
    verify_subcredential()
    test_layer_cipher()
    # test_decrypt_known()
