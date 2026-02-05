#!/usr/bin/env python3
"""
Parse test_descriptor.txt using the same logic as RustBalance,
to verify the parsing and decryption works end-to-end.
"""

import base64
import hashlib
import struct

def base64_decode(s):
    """Decode base64, handling padding"""
    missing_padding = len(s) % 4
    if missing_padding:
        s += '=' * (4 - missing_padding)
    return base64.b64decode(s)

def extract_blinded_key_from_cert(cert):
    """Extract blinded key from certificate extension 0x04"""
    if len(cert) < 40:
        raise ValueError(f"Certificate too short: {len(cert)} bytes")
    
    version = cert[0]
    cert_type = cert[1]
    print(f"  Cert type: 0x{cert_type:02x}")
    
    n_extensions = cert[39]
    offset = 40
    
    for i in range(n_extensions):
        ext_len = int.from_bytes(cert[offset:offset+2], 'big')
        ext_type = cert[offset+2]
        
        if ext_type == 0x04 and ext_len == 32:
            return cert[offset+4:offset+4+32]
        
        offset += 4 + ext_len
    
    raise ValueError("No blinded key found")

def derive_subcredential(identity_key, blinded_key):
    credential = hashlib.sha3_256(b'credential' + identity_key).digest()
    return hashlib.sha3_256(b'subcredential' + credential + blinded_key).digest()

def decrypt_layer(ciphertext, blinded_key, subcredential, revision_counter, string_constant):
    salt = ciphertext[:16]
    encrypted = ciphertext[16:-32]
    mac = ciphertext[-32:]
    
    print(f"  Salt: {salt.hex()}")
    print(f"  Encrypted: {len(encrypted)} bytes")
    print(f"  MAC: {mac.hex()}")
    
    kdf_input = blinded_key + subcredential + struct.pack('>Q', revision_counter) + salt + string_constant
    keys = hashlib.shake_256(kdf_input).digest(80)
    
    secret_key = keys[:32]
    secret_iv = keys[32:48]
    mac_key = keys[48:80]
    
    print(f"  mac_key: {mac_key.hex()}")
    
    mac_input = struct.pack('>Q', 32) + mac_key + struct.pack('>Q', 16) + salt + encrypted
    computed_mac = hashlib.sha3_256(mac_input).digest()
    
    print(f"  Computed MAC: {computed_mac.hex()}")
    print(f"  MAC Match: {computed_mac == mac}")
    
    if computed_mac != mac:
        raise ValueError("MAC verification failed!")
    
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(secret_key), modes.CTR(secret_iv))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted) + decryptor.finalize()

def parse_descriptor(raw):
    version = revision_counter = 0
    in_encrypted = in_cert = False
    encrypted_lines = []
    cert_lines = []
    
    for line in raw.split('\n'):
        if line.startswith('hs-descriptor '):
            version = int(line.split()[1])
        elif line.startswith('revision-counter '):
            revision_counter = int(line.split()[1])
        elif line == '-----BEGIN MESSAGE-----':
            in_encrypted = True
        elif line == '-----END MESSAGE-----':
            in_encrypted = False
        elif in_encrypted:
            encrypted_lines.append(line)
        elif line == '-----BEGIN ED25519 CERT-----':
            in_cert = True
        elif line == '-----END ED25519 CERT-----':
            in_cert = False
        elif in_cert:
            cert_lines.append(line)
    
    encrypted_body = base64_decode(''.join(encrypted_lines))
    signing_key_cert = base64_decode(''.join(cert_lines))
    blinded_key = extract_blinded_key_from_cert(signing_key_cert)
    
    return version, revision_counter, encrypted_body, bytes(blinded_key)

def main():
    with open('test_descriptor.txt', 'r') as f:
        raw = f.read()
    
    print("=== Parsing descriptor ===")
    version, revision_counter, encrypted_body, blinded_key = parse_descriptor(raw)
    print(f"Version: {version}, Rev: {revision_counter}")
    print(f"Encrypted: {len(encrypted_body)} bytes")
    print(f"Blinded key: {blinded_key.hex()}")
    
    with open('test_keys.txt', 'r') as f:
        keys = dict(line.strip().split('=', 1) for line in f if '=' in line)
    
    onion = keys['onion_address'].replace('.onion', '').upper()
    while len(onion) % 8: onion += '='
    identity_key = base64.b32decode(onion)[:32]
    
    subcredential = derive_subcredential(identity_key, blinded_key)
    print(f"Subcredential: {subcredential.hex()}")
    
    print("\n=== Decrypting ===")
    outer = decrypt_layer(encrypted_body, blinded_key, subcredential, revision_counter, b'hsdir-superencrypted-data')
    print(f"\nSUCCESS! Decrypted {len(outer)} bytes")
    print(f"First 200 chars: {outer[:200]}")

if __name__ == "__main__":
    main()
