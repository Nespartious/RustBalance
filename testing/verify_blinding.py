#!/usr/bin/env python3
"""Use stem (official Tor Python lib) to compute blinded key and compare with our computation."""
import hashlib
import struct
import time
import os
import binascii
import socket

# Import stem for Tor's official blinding implementation
from stem.descriptor.hidden_service import HiddenServiceDescriptorV3

def compute_time_period():
    now = int(time.time())
    minutes_since_epoch = now // 60
    adjusted = minutes_since_epoch - 720
    period_num = adjusted // 1440
    return period_num

def our_compute_blinding_factor(pubkey_bytes, period_num, period_length_minutes=1440):
    """Our SHA3-256 blinding factor computation."""
    h = hashlib.sha3_256()
    h.update(b"Derive temporary signing key\x00")
    h.update(pubkey_bytes)
    basepoint = b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"
    h.update(basepoint)
    h.update(b"key-blind")
    h.update(struct.pack(">Q", period_num))
    h.update(struct.pack(">Q", period_length_minutes))
    return h.digest()

def get_tor_descriptor_blinded_key():
    """Get Tor's actual descriptor and parse the blinded key from it."""
    cookie = open("/run/tor/control.authcookie", "rb").read()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 9051))
    s.settimeout(10)
    s.sendall(b"AUTHENTICATE " + binascii.hexlify(cookie) + b"\r\n")
    resp = s.recv(256)
    
    # Get full descriptor
    s.sendall(b"GETINFO hs/service/desc/id/763r3ghcxy3l6efxeaub2gzscbjaft3q62npnqjiyqbhqnzb3yeoykqd\r\n")
    resp = b""
    while True:
        try:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
            if b"\r\n.\r\n" in resp or b"552" in resp:
                break
        except:
            break
    s.sendall(b"QUIT\r\n")
    s.close()
    
    # Extract the descriptor text
    text = resp.decode(errors="replace")
    # Find the first cert
    import base64
    lines = text.split("\n")
    in_cert = False
    cert_b64 = ""
    
    for line in lines:
        line = line.strip()
        if "BEGIN ED25519 CERT" in line:
            in_cert = True
            cert_b64 = ""
            continue
        if "END ED25519 CERT" in line:
            in_cert = False
            cert_bytes = base64.b64decode(cert_b64)
            # Cert structure:
            # byte 0: version
            # byte 1: cert type
            # bytes 2-5: expiration (hours since epoch, big-endian)
            # byte 6: cert key type
            # bytes 7-38: certified key (32 bytes)
            # byte 39: N extensions
            # Extension: 2-byte len, 1-byte type, 1-byte flags, data
            # The "signed-with-ed25519-key" extension (type 0x04) contains the signer
            certified_key = cert_bytes[7:39]
            n_ext = cert_bytes[39]
            offset = 40
            signing_key = None
            for i in range(n_ext):
                ext_len = struct.unpack(">H", cert_bytes[offset:offset+2])[0]
                ext_type = cert_bytes[offset+2]
                if ext_type == 0x04 and ext_len == 32:
                    signing_key = cert_bytes[offset+4:offset+4+32]
                offset += 4 + ext_len
            
            # In desc-signing-key cert (type 0x08):
            # certified_key = descriptor signing key
            # signing_key (ext 0x04) = blinded identity key
            if cert_bytes[1] == 0x08:
                return signing_key, certified_key
            break
        if in_cert:
            cert_b64 += line
    
    return None, None

def try_stem_blinding():
    """Use stem's internal blinding if available."""
    try:
        # stem's descriptor module may have helper functions
        # Let's check what stem provides
        from stem.descriptor.hidden_service import HiddenServiceDescriptorV3
        from stem.descriptor import hidden_service
        
        # Check if stem has a blinding function
        if hasattr(hidden_service, '_blinded_pubkey'):
            print("Found stem._blinded_pubkey")
        
        # Look for crypto functions in stem
        import stem.descriptor.hidden_service as hs_mod
        funcs = [f for f in dir(hs_mod) if 'blind' in f.lower() or 'key' in f.lower()]
        print(f"Stem functions with 'blind' or 'key': {funcs}")
        
        # Check stem's crypto module
        try:
            from stem import descriptor
            from stem.descriptor import certificate  
            print(f"stem.descriptor functions: {[f for f in dir(descriptor) if not f.startswith('_')]}")
        except Exception as e:
            print(f"stem.descriptor.certificate: {e}")
            
    except Exception as e:
        print(f"stem error: {e}")

def test_ed25519_operations():
    """Test basic Ed25519 operations to verify our implementation."""
    try:
        from nacl.signing import SigningKey, VerifyKey
        from nacl.encoding import RawEncoder
        
        # Test: generate a key, verify the pubkey matches
        sk = SigningKey.generate()
        pk = sk.verify_key
        print(f"PyNaCl test - generated key OK")
        
        # Load our identity key
        pubkey_hex = "ffb71d98e2be36bf10b720281d1b32105202cf70f69af6c128c402783721de08"
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        vk = VerifyKey(pubkey_bytes)
        print(f"Identity key loaded: {vk.encode().hex()}")
        
    except ImportError:
        print("PyNaCl not available")
    except Exception as e:
        print(f"PyNaCl error: {e}")

def test_with_nacl_scalarmult():
    """Use PyNaCl/libsodium for Ed25519 scalar multiplication."""
    try:
        # Try using ctypes to call libsodium directly
        import ctypes
        import ctypes.util
        
        lib = ctypes.util.find_library('sodium')
        if lib:
            sodium = ctypes.cdll.LoadLibrary(lib)
            print(f"Loaded libsodium: {lib}")
            
            # Check if crypto_scalarmult_ed25519 is available
            try:
                func = sodium.crypto_scalarmult_ed25519_noclamp
                print("crypto_scalarmult_ed25519_noclamp available")
                
                pubkey_hex = "ffb71d98e2be36bf10b720281d1b32105202cf70f69af6c128c402783721de08"
                pubkey_bytes = bytes.fromhex(pubkey_hex)
                
                # Current time period
                tp = compute_time_period()
                
                # Compute blinding factor  
                h = our_compute_blinding_factor(pubkey_bytes, tp)
                
                # Clamp
                b = bytearray(h)
                b[0] &= 248
                b[31] &= 63
                b[31] |= 64
                clamped = bytes(b)
                
                # Use libsodium for scalar mult
                result = ctypes.create_string_buffer(32)
                scalar = ctypes.create_string_buffer(clamped)
                point = ctypes.create_string_buffer(pubkey_bytes)
                
                # crypto_scalarmult_ed25519_noclamp(result, scalar, point)
                ret = func(result, scalar, point)
                if ret == 0:
                    blinded = bytes(result)
                    print(f"libsodium blinded key: {blinded.hex()}")
                else:
                    print(f"libsodium scalarmult returned: {ret}")
                    
            except AttributeError:
                print("crypto_scalarmult_ed25519_noclamp not available")
                # Try with crypto_scalarmult_ed25519
                try:
                    func = sodium.crypto_scalarmult_ed25519
                    print("Using crypto_scalarmult_ed25519 (with clamping)")
                except AttributeError:
                    print("No ed25519 scalarmult available in libsodium")
        else:
            print("libsodium not found")
    except Exception as e:
        print(f"libsodium error: {e}")

def main():
    pubkey_hex = "ffb71d98e2be36bf10b720281d1b32105202cf70f69af6c128c402783721de08"
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    tp = compute_time_period()
    
    print(f"Identity pubkey: {pubkey_hex}")
    print(f"Current time period: {tp}")
    print()
    
    # 1. Get Tor's actual blinded key
    print("=== TOR'S BLINDED KEY ===")
    blinded_key, signing_key = get_tor_descriptor_blinded_key()
    if blinded_key:
        print(f"Tor's blinded key: {blinded_key.hex()}")
        print(f"Descriptor signing key: {signing_key.hex()}")
    
    # 2. Our blinding factor
    print("\n=== OUR BLINDING FACTOR ===")
    h = our_compute_blinding_factor(pubkey_bytes, tp)
    b = bytearray(h)
    b[0] &= 248
    b[31] &= 63
    b[31] |= 64
    clamped = bytes(b)
    print(f"Period {tp}: hash={h.hex()}")
    print(f"Clamped: {clamped.hex()}")
    
    # 3. Try stem
    print("\n=== STEM LIBRARY ===")
    try_stem_blinding()
    
    # 4. Test PyNaCl
    print("\n=== PyNaCl TEST ===")
    test_ed25519_operations()
    
    # 5. Try libsodium
    print("\n=== LIBSODIUM SCALAR MULT ===")
    test_with_nacl_scalarmult()

if __name__ == "__main__":
    main()
