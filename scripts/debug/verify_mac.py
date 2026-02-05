#!/usr/bin/env python3
"""Verify MAC computation against Tor's official implementation."""

import socket
import base64
import re
import hashlib

def fetch_descriptor(onion_address):
    """Fetch descriptor via Tor control port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 9051))
    sock.settimeout(5)  # Short timeout for each recv
    
    sock.send(b'AUTHENTICATE "pass"\r\n')
    sock.recv(1024)
    
    sock.send(b'SETEVENTS HS_DESC_CONTENT\r\n')
    sock.recv(1024)
    
    sock.send(f'HSFETCH {onion_address}\r\n'.encode())
    sock.recv(1024)
    
    data = b''
    while True:
        try:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
            if b'650 OK' in data:
                break
        except socket.timeout:
            # If we have data and timeout, we're done
            if data:
                break
            raise
    
    sock.close()
    return data

def derive_keys_shake256(secret_input, salt, string_constant):
    """Derive keys using SHAKE-256 XOF."""
    import hashlib
    xof = hashlib.shake_256()
    xof.update(secret_input)
    xof.update(salt)
    xof.update(string_constant)
    output = xof.digest(80)  # 32 + 16 + 32
    return output[:32], output[32:48], output[48:80]

def compute_mac(mac_key, salt, encrypted):
    """Compute MAC following Tor's build_mac function."""
    mac_key_len = len(mac_key).to_bytes(8, 'big')
    salt_len = len(salt).to_bytes(8, 'big')
    
    hasher = hashlib.sha3_256()
    hasher.update(mac_key_len)
    hasher.update(mac_key)
    hasher.update(salt_len)
    hasher.update(salt)
    hasher.update(encrypted)
    return hasher.digest()

def main():
    # Fetch descriptor
    address = 'esnymppkuwdhwam6vzthfvtl2i2y64rwwyt23gp63xmctndqp5tvgaad'
    print(f'Fetching descriptor for {address}...')
    data = fetch_descriptor(address)
    desc = data.decode('utf-8', errors='replace')
    
    # Extract superencrypted body
    match = re.search(r'-----BEGIN MESSAGE-----\r?\n(.+?)\r?\n-----END MESSAGE-----', desc, re.DOTALL)
    if not match:
        print('MESSAGE block not found')
        print(f'Data:\n{desc[:2000]}')
        return
    
    body_b64 = match.group(1).replace('\n', '').replace('\r', '')
    body = base64.b64decode(body_b64)
    
    print(f'\n=== Superencrypted body ===')
    print(f'Total length: {len(body)} bytes')
    
    salt = body[:16]
    encrypted = body[16:-32]
    expected_mac = body[-32:]
    
    print(f'Salt (16 bytes): {salt.hex()}')
    print(f'Encrypted data: {len(encrypted)} bytes')
    print(f'Expected MAC (32 bytes): {expected_mac.hex()}')
    
    # Extract blinded key from cert
    cert_match = re.search(r'descriptor-signing-key-cert\r?\n-----BEGIN ED25519 CERT-----\r?\n(.+?)\r?\n-----END ED25519 CERT-----', desc, re.DOTALL)
    if cert_match:
        cert_b64 = cert_match.group(1).replace('\n', '').replace('\r', '')
        cert = base64.b64decode(cert_b64)
        # Blinded key is at offset 44, length 32 (extension type 0x04)
        blinded_key = cert[44:76]
        print(f'\n=== Blinded key (from cert) ===')
        print(f'Blinded key: {blinded_key.hex()}')
    else:
        print('Could not find cert')
        return
    
    # Extract revision counter
    rev_match = re.search(r'revision-counter (\d+)', desc)
    if rev_match:
        revision = int(rev_match.group(1))
        print(f'Revision counter: {revision}')
    else:
        print('Could not find revision counter')
        return
    
    # Derive identity key from onion address
    onion_part = address.replace('.onion', '')
    # Pad to multiple of 8 for base32
    padding_needed = (8 - len(onion_part) % 8) % 8
    decoded = base64.b32decode(onion_part.upper() + '=' * padding_needed)
    identity_key = decoded[:32]
    print(f'\n=== Identity key (from onion) ===')
    print(f'Identity key: {identity_key.hex()}')
    
    # Compute subcredential
    credential = hashlib.sha3_256(b'credential' + identity_key).digest()
    subcredential = hashlib.sha3_256(b'subcredential' + credential + blinded_key).digest()
    print(f'\n=== Subcredential ===')
    print(f'Subcredential: {subcredential.hex()}')
    
    # Build secret_input
    # secret_input = SECRET_DATA || subcredential || INT_8(revision_counter)
    # SECRET_DATA for outer layer = blinded_key
    secret_input = blinded_key + subcredential + revision.to_bytes(8, 'big')
    print(f'\n=== Secret input ===')
    print(f'secret_input ({len(secret_input)} bytes): {secret_input.hex()}')
    
    # Derive keys
    string_constant = b'hsdir-superencrypted-data'
    secret_key, secret_iv, mac_key = derive_keys_shake256(secret_input, salt, string_constant)
    
    print(f'\n=== Derived keys ===')
    print(f'SECRET_KEY: {secret_key.hex()}')
    print(f'SECRET_IV:  {secret_iv.hex()}')
    print(f'MAC_KEY:    {mac_key.hex()}')
    
    # Compute MAC
    computed_mac = compute_mac(mac_key, salt, encrypted)
    print(f'\n=== MAC verification ===')
    print(f'Expected MAC: {expected_mac.hex()}')
    print(f'Computed MAC: {computed_mac.hex()}')
    
    if computed_mac == expected_mac:
        print('\n✓ MAC MATCHES!')
    else:
        print('\n✗ MAC MISMATCH!')
        print('\nDebugging info:')
        print(f'  mac_key_len bytes: {len(mac_key).to_bytes(8, "big").hex()}')
        print(f'  salt_len bytes:    {len(salt).to_bytes(8, "big").hex()}')
        print(f'  encrypted first 32: {encrypted[:32].hex()}')
        print(f'  encrypted last 32:  {encrypted[-32:].hex()}')

if __name__ == '__main__':
    main()
