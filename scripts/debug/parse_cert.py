#!/usr/bin/env python3
"""Parse certificate to verify blinded key extraction."""

import socket
import base64
import re

def fetch_descriptor():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 9051))
    sock.settimeout(30)

    sock.send(b'AUTHENTICATE "pass"\r\n')
    sock.recv(1024)
    sock.send(b'SETEVENTS HS_DESC_CONTENT\r\n')  
    sock.recv(1024)
    sock.send(b'HSFETCH esnymppkuwdhwam6vzthfvtl2i2y64rwwyt23gp63xmctndqp5tvgaad\r\n')
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
            if data:
                break
            raise

    sock.close()
    return data.decode('utf-8', errors='replace')

def main():
    desc = fetch_descriptor()
    
    # Extract certificate
    cert_match = re.search(r'descriptor-signing-key-cert\r?\n-----BEGIN ED25519 CERT-----\r?\n(.+?)\r?\n-----END ED25519 CERT-----', desc, re.DOTALL)
    if not cert_match:
        print('Certificate not found')
        return
    
    cert_b64 = cert_match.group(1).replace('\n', '').replace('\r', '')
    cert = base64.b64decode(cert_b64)
    
    print(f'Certificate raw ({len(cert)} bytes):')
    print(f'  {cert.hex()}')
    print()
    
    # Parse certificate structure (Tor Ed25519 cert format)
    version = cert[0]
    cert_type = cert[1]
    expiry = int.from_bytes(cert[2:6], 'big')
    key_type = cert[6]
    certified_key = cert[7:39]
    n_extensions = cert[39]
    
    print(f'Certificate structure:')
    print(f'  Version: {version}')
    print(f'  Cert type: {cert_type}')
    print(f'  Expiration (hours since epoch): {expiry}')
    print(f'  Key type: {key_type}')
    print(f'  Certified key (SIGNING KEY): {certified_key.hex()}')
    print(f'  N_extensions: {n_extensions}')
    print()
    
    # Parse extensions
    offset = 40
    blinded_key = None
    for i in range(n_extensions):
        if offset + 4 > len(cert):
            break
        ext_len = int.from_bytes(cert[offset:offset+2], 'big')
        ext_type = cert[offset+2]
        ext_flags = cert[offset+3]
        ext_data = cert[offset+4:offset+4+ext_len-2]
        
        print(f'  Extension {i}:')
        print(f'    Length: {ext_len}')
        print(f'    Type: {ext_type}')
        print(f'    Flags: {ext_flags}')
        print(f'    Data ({len(ext_data)} bytes): {ext_data.hex()}')
        
        # Type 4 = signing key (the BLINDED public key that signed this cert)
        if ext_type == 4:
            blinded_key = ext_data
            print(f'    -> BLINDED PUBLIC KEY (from extension)')
        
        offset += 4 + ext_len - 2
    
    print()
    
    # According to Tor spec, the blinded key is the SIGNING KEY of the descriptor cert
    # which is in extension type 0x04
    if blinded_key:
        print(f'Blinded key (from ext 0x04): {blinded_key.hex()}')
    
    # Also, the signing_key is stored directly in the cert itself
    # For descriptor certs, the signing_key_included flag should be set
    print(f'Certified key in cert body: {certified_key.hex()}')
    
    # Compare with RustBalance
    rb_blinded = '35583b72129f59ed130df845d1b45eabfe9b013817e9fef1d37a9544da1896b0'
    print()
    print(f'RustBalance blinded key:    {rb_blinded}')
    if blinded_key:
        print(f'Match with extension:       {blinded_key.hex() == rb_blinded}')
    print(f'Match with certified_key:   {certified_key.hex() == rb_blinded}')

if __name__ == '__main__':
    main()
