#!/usr/bin/env python3
"""Generate a Tor-format Ed25519 master key for RustBalance."""
import os
import sys
import hashlib
import base64

try:
    from nacl.signing import SigningKey
except ImportError:
    print("Installing pynacl...")
    os.system("pip3 install pynacl --break-system-packages")
    from nacl.signing import SigningKey

def generate_tor_key(output_dir):
    """Generate Tor-format expanded Ed25519 key."""
    # Generate random 32-byte seed
    seed = os.urandom(32)
    
    # Create signing key from seed
    signing_key = SigningKey(seed)
    public_key = signing_key.verify_key
    
    # Expand the secret key (Tor uses expanded format)
    # SHA-512 the seed, clamp, this gives 64-byte expanded key
    h = hashlib.sha512(seed).digest()
    expanded = bytearray(h)
    # Clamp
    expanded[0] &= 248
    expanded[31] &= 127
    expanded[31] |= 64
    
    # Tor format: "== ed25519v1-secret: type0 ==\x00\x00\x00" (32 bytes) + 64 bytes expanded key
    header = b"== ed25519v1-secret: type0 ==\x00\x00\x00"
    secret_content = header + bytes(expanded)
    
    # Public key format: "== ed25519v1-public: type0 ==\x00\x00\x00" (32 bytes) + 32 bytes pubkey
    pub_header = b"== ed25519v1-public: type0 ==\x00\x00\x00"
    public_content = pub_header + bytes(public_key)
    
    # Derive onion address
    # onion_address = base32(pubkey + checksum + version)
    # checksum = sha3_256(".onion checksum" + pubkey + version)[:2]
    from hashlib import sha3_256
    version = b'\x03'
    checksum_input = b".onion checksum" + bytes(public_key) + version
    checksum = sha3_256(checksum_input).digest()[:2]
    onion_bytes = bytes(public_key) + checksum + version
    onion_address = base64.b32encode(onion_bytes).decode().lower() + ".onion"
    
    # Write files
    os.makedirs(output_dir, exist_ok=True)
    
    secret_path = os.path.join(output_dir, "hs_ed25519_secret_key")
    public_path = os.path.join(output_dir, "hs_ed25519_public_key")
    hostname_path = os.path.join(output_dir, "hostname")
    
    with open(secret_path, "wb") as f:
        f.write(secret_content)
    os.chmod(secret_path, 0o600)
    
    with open(public_path, "wb") as f:
        f.write(public_content)
    
    with open(hostname_path, "w") as f:
        f.write(onion_address + "\n")
    
    print(f"Generated master key in {output_dir}")
    print(f"Master onion address: {onion_address}")
    print(f"Secret key: {secret_path}")
    print(f"Public key: {public_path}")

if __name__ == "__main__":
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "/home/user/master_key"
    generate_tor_key(output_dir)
