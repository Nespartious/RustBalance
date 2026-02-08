#!/usr/bin/env python3
"""Extract Tor's actual blinded key from descriptor cert and compare with our computation."""
import socket
import binascii
import base64
import hashlib
import struct
import time
import os

def get_full_descriptor():
    """Query Tor's control port for the full descriptor."""
    cookie = open("/run/tor/control.authcookie", "rb").read()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 9051))
    s.settimeout(10)
    
    s.sendall(b"AUTHENTICATE " + binascii.hexlify(cookie) + b"\r\n")
    auth_resp = s.recv(256).decode().strip()
    print(f"AUTH: {auth_resp}")
    
    s.sendall(b"GETINFO hs/service/desc/id/763r3ghcxy3l6efxeaub2gzscbjaft3q62npnqjiyqbhqnzb3yeoykqd\r\n")
    resp = b""
    while True:
        try:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
            if b"\r\n.\r\n250 OK" in resp or b"552" in resp:
                break
        except socket.timeout:
            break
    
    s.sendall(b"QUIT\r\n")
    s.close()
    return resp.decode(errors="replace")

def extract_blinded_key(descriptor_text):
    """Extract the blinded key from the descriptor-signing-key-cert."""
    # Find the cert between BEGIN/END ED25519 CERT markers
    lines = descriptor_text.split("\n")
    in_cert = False
    cert_b64 = ""
    cert_count = 0
    
    for line in lines:
        line = line.strip()
        if "BEGIN ED25519 CERT" in line:
            in_cert = True
            cert_b64 = ""
            continue
        if "END ED25519 CERT" in line:
            in_cert = False
            cert_count += 1
            # Decode the cert
            try:
                cert_bytes = base64.b64decode(cert_b64)
                print(f"\nCert #{cert_count} ({len(cert_bytes)} bytes):")
                print(f"  Version: {cert_bytes[0]}")
                print(f"  Cert type: 0x{cert_bytes[1]:02x}")
                # Expiration: 4 bytes, hours since epoch
                exp_hours = struct.unpack(">I", cert_bytes[2:6])[0]
                exp_time = exp_hours * 3600
                print(f"  Expiration: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(exp_time))}")
                print(f"  Cert key type: {cert_bytes[6]}")
                # Certified key: 32 bytes at offset 7
                certified_key = cert_bytes[7:39]
                print(f"  Certified key (blinded key): {certified_key.hex()}")
                
                # Number of extensions
                n_ext = cert_bytes[39]
                print(f"  Number of extensions: {n_ext}")
                
                # Parse extensions to find the signing key
                offset = 40
                for i in range(n_ext):
                    if offset + 4 > len(cert_bytes):
                        break
                    ext_len = struct.unpack(">H", cert_bytes[offset:offset+2])[0]
                    ext_type = cert_bytes[offset+2]
                    ext_flags = cert_bytes[offset+3]
                    ext_data = cert_bytes[offset+4:offset+4+ext_len]
                    print(f"  Extension {i}: type=0x{ext_type:02x}, flags=0x{ext_flags:02x}, len={ext_len}")
                    if ext_type == 0x04 and ext_len == 32:  # Signed-with-ed25519-key
                        print(f"    Signing key: {ext_data.hex()}")
                    offset += 4 + ext_len
                
                # Signature: last 64 bytes
                sig = cert_bytes[-64:]
                print(f"  Signature: {sig.hex()[:32]}...")
                
            except Exception as e:
                print(f"  Error decoding cert: {e}")
            continue
        if in_cert:
            cert_b64 += line
    
    # Also find revision-counter
    for line in lines:
        if "revision-counter" in line:
            print(f"\n{line.strip()}")

def compute_blinding(pubkey_hex, period_num):
    """Compute our blinding for comparison."""
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    
    h = hashlib.sha3_256()
    h.update(b"Derive temporary signing key\x00")
    h.update(pubkey_bytes)
    basepoint = b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"
    h.update(basepoint)
    h.update(b"key-blind")
    h.update(struct.pack(">Q", period_num))
    h.update(struct.pack(">Q", 1440))
    
    result = h.digest()
    
    # Clamp
    b = bytearray(result)
    b[0] &= 248
    b[31] &= 63
    b[31] |= 64
    
    return bytes(b), result

def main():
    pubkey_hex = "ffb71d98e2be36bf10b720281d1b32105202cf70f69af6c128c402783721de08"
    
    # Compute current time period
    now = int(time.time())
    minutes_since_epoch = now // 60
    adjusted = minutes_since_epoch - 720
    current_tp = adjusted // 1440
    next_tp = current_tp + 1
    
    print(f"Current time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(now))}")
    print(f"Current period: {current_tp}, Next: {next_tp}")
    print(f"Identity pubkey: {pubkey_hex}")
    
    print("\n" + "=" * 60)
    print("TOR'S DESCRIPTOR (from GETINFO)")
    print("=" * 60)
    desc = get_full_descriptor()
    extract_blinded_key(desc)
    
    print("\n" + "=" * 60)
    print("OUR BLINDING COMPUTATION")
    print("=" * 60)
    for tp in [current_tp, next_tp]:
        clamped, raw_hash = compute_blinding(pubkey_hex, tp)
        print(f"Period {tp}: hash={raw_hash.hex()}, clamped={clamped.hex()}")

if __name__ == "__main__":
    main()
