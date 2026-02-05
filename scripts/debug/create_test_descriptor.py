#!/usr/bin/env python3
"""
Create a test descriptor with known values, then verify RustBalance can decrypt it.
This will help us debug the MAC verification issue.
"""

import hashlib
import struct
import base64
import os

try:
    from stem.descriptor.hidden_service import HiddenServiceDescriptorV3, InnerLayer, OuterLayer
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Run: pip install stem cryptography")
    exit(1)

def test_create_and_verify():
    """Create a descriptor with known keys and verify we can decrypt it"""
    
    print("=== Creating test descriptor with known keys ===\n")
    
    # Generate deterministic keys (for reproducibility)
    identity_key = Ed25519PrivateKey.from_private_bytes(b'A' * 32)
    signing_key = Ed25519PrivateKey.from_private_bytes(b'B' * 32)
    
    # Generate blinding nonce
    blinding_nonce = b'C' * 32
    
    # Create the descriptor
    desc = HiddenServiceDescriptorV3.create(
        identity_key=identity_key,
        signing_key=signing_key,
        blinding_nonce=blinding_nonce,
        revision_counter=12345,
    )
    
    # Get the onion address
    onion_address = HiddenServiceDescriptorV3.address_from_identity_key(identity_key)
    print(f"Onion address: {onion_address}")
    
    # Get the blinded key from the certificate
    blinded_key = desc.signing_cert.signing_key()
    print(f"Blinded key: {blinded_key.hex()}")
    
    # Get the identity key bytes
    from cryptography.hazmat.primitives import serialization
    identity_pubkey_bytes = identity_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    print(f"Identity key: {identity_pubkey_bytes.hex()}")
    
    # Compute subcredential
    credential = hashlib.sha3_256(b'credential' + identity_pubkey_bytes).digest()
    subcredential = hashlib.sha3_256(b'subcredential' + credential + blinded_key).digest()
    print(f"Subcredential: {subcredential.hex()}")
    
    # Get the revision counter
    print(f"Revision counter: {desc.revision_counter}")
    
    # Get the raw superencrypted blob
    superencrypted = desc.superencrypted
    print(f"\nSuperencrypted (base64, first 100 chars): {superencrypted[:100]}...")
    
    # Decode the superencrypted blob
    if superencrypted.startswith('-----BEGIN MESSAGE-----\n'):
        superencrypted = superencrypted[24:]
    if superencrypted.endswith('\n-----END MESSAGE-----'):
        superencrypted = superencrypted[:-22]
    
    encrypted_blob = base64.b64decode(superencrypted)
    print(f"Encrypted blob: {len(encrypted_blob)} bytes")
    
    # Extract salt, ciphertext, mac
    salt = encrypted_blob[:16]
    ciphertext = encrypted_blob[16:-32]
    expected_mac = encrypted_blob[-32:]
    
    print(f"\nExtracted:")
    print(f"  Salt: {salt.hex()}")
    print(f"  Ciphertext: {len(ciphertext)} bytes")
    print(f"  Ciphertext first 32: {ciphertext[:32].hex()}")
    print(f"  Expected MAC: {expected_mac.hex()}")
    
    # Now compute the MAC ourselves
    S_KEY_LEN = 32
    S_IV_LEN = 16
    MAC_LEN = 32
    
    constant = b'hsdir-superencrypted-data'
    
    kdf_input = blinded_key + subcredential + struct.pack('>Q', desc.revision_counter) + salt + constant
    print(f"\nKDF input ({len(kdf_input)} bytes): {kdf_input.hex()}")
    
    kdf = hashlib.shake_256(kdf_input)
    keys = kdf.digest(S_KEY_LEN + S_IV_LEN + MAC_LEN)
    
    secret_key = keys[:S_KEY_LEN]
    secret_iv = keys[S_KEY_LEN:S_KEY_LEN + S_IV_LEN]
    mac_key = keys[S_KEY_LEN + S_IV_LEN:]
    
    print(f"\nDerived keys:")
    print(f"  secret_key: {secret_key.hex()}")
    print(f"  secret_iv: {secret_iv.hex()}")
    print(f"  mac_key: {mac_key.hex()}")
    
    # Compute MAC
    mac_prefix = struct.pack('>Q', len(mac_key)) + mac_key + struct.pack('>Q', len(salt)) + salt
    computed_mac = hashlib.sha3_256(mac_prefix + ciphertext).digest()
    
    print(f"\nMAC verification:")
    print(f"  Computed MAC: {computed_mac.hex()}")
    print(f"  Expected MAC: {expected_mac.hex()}")
    print(f"  Match: {computed_mac == expected_mac}")
    
    # Now try to decrypt using stem
    print("\n=== Testing stem decryption ===")
    try:
        inner_layer = desc.decrypt(onion_address)
        print(f"SUCCESS! Decrypted inner layer: {type(inner_layer)}")
        print(f"Introduction points: {len(inner_layer.introduction_points)}")
    except Exception as e:
        print(f"DECRYPTION FAILED: {e}")
        import traceback
        traceback.print_exc()
    
    # Save the raw descriptor for testing with RustBalance
    raw_descriptor = str(desc)
    print(f"\n=== Raw descriptor (first 500 chars) ===")
    print(raw_descriptor[:500])
    
    # Save to file
    with open('test_descriptor.txt', 'w') as f:
        f.write(raw_descriptor)
    print(f"\nSaved descriptor to test_descriptor.txt")
    
    # Save key info for RustBalance testing
    with open('test_keys.txt', 'w') as f:
        f.write(f"onion_address={onion_address}\n")
        f.write(f"identity_key={identity_pubkey_bytes.hex()}\n")
        f.write(f"blinded_key={blinded_key.hex()}\n")
        f.write(f"subcredential={subcredential.hex()}\n")
        f.write(f"revision_counter={desc.revision_counter}\n")
    print("Saved keys to test_keys.txt")

if __name__ == "__main__":
    test_create_and_verify()
