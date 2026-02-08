#!/usr/bin/env python3
"""Get Tor's blinded key from control port and compute our own for comparison."""
import socket
import binascii
import hashlib
import struct
import time
import os

def get_tor_blinded_key():
    """Query Tor's control port for the current descriptor's blinded key."""
    cookie_path = "/run/tor/control.authcookie"
    if not os.path.exists(cookie_path):
        print(f"Cookie file not found at {cookie_path}")
        return None
    
    cookie = open(cookie_path, "rb").read()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 9051))
    s.settimeout(10)
    
    # Authenticate
    s.sendall(b"AUTHENTICATE " + binascii.hexlify(cookie) + b"\r\n")
    auth_resp = s.recv(256).decode().strip()
    print(f"AUTH: {auth_resp}")
    
    # Get descriptor for our HS
    s.sendall(b"GETINFO hs/service/desc/id/763r3ghcxy3l6efxeaub2gzscbjaft3q62npnqjiyqbhqnzb3yeoykqd\r\n")
    resp = b""
    while True:
        try:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
            if b"250 OK" in resp or b"552" in resp:
                break
        except socket.timeout:
            break
    
    s.sendall(b"QUIT\r\n")
    s.close()
    
    lines = resp.decode(errors="replace").split("\n")
    for line in lines:
        low = line.lower().strip()
        if "blinded" in low or "hs-descriptor" in low or "revision-counter" in low:
            print(f"  {line.strip()[:200]}")

def compute_time_period():
    """Compute the current time period number."""
    now = int(time.time())
    minutes_since_epoch = now // 60
    rotation_offset = 720  # 12 hours in minutes
    period_length = 1440   # 24 hours in minutes
    adjusted = minutes_since_epoch - rotation_offset
    period_num = adjusted // period_length
    next_period = period_num + 1
    print(f"\nCurrent time: {now} ({time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(now))})")
    print(f"Minutes since epoch: {minutes_since_epoch}")
    print(f"Adjusted (- {rotation_offset}): {adjusted}")
    print(f"Current period: {period_num}")
    print(f"Next period: {next_period}")
    return period_num, next_period

def compute_blinding_factor(pubkey_bytes, period_num, period_length_minutes):
    """Compute the blinding factor as SHA3-256 hash."""
    h = hashlib.sha3_256()
    
    # BLIND_STRING with null terminator
    blind_string = b"Derive temporary signing key\x00"
    h.update(blind_string)
    
    # Public key (32 bytes)
    h.update(pubkey_bytes)
    
    # Ed25519 basepoint string
    basepoint = b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"
    h.update(basepoint)
    
    # Nonce N = "key-blind" || period_num (8 bytes BE) || period_length (8 bytes BE)
    h.update(b"key-blind")
    h.update(struct.pack(">Q", period_num))
    h.update(struct.pack(">Q", period_length_minutes))
    
    result = h.digest()
    
    print(f"\n  Blinding factor hash inputs:")
    print(f"    blind_string ({len(blind_string)} bytes): {blind_string.hex()}")
    print(f"    pubkey ({len(pubkey_bytes)} bytes): {pubkey_bytes.hex()}")
    print(f"    basepoint ({len(basepoint)} bytes): (shown by len)")
    print(f"    nonce prefix: key-blind")
    print(f"    period_num: {period_num} -> BE: {struct.pack('>Q', period_num).hex()}")
    print(f"    period_len: {period_length_minutes} -> BE: {struct.pack('>Q', period_length_minutes).hex()}")
    print(f"    SHA3-256 result: {result.hex()}")
    
    return result

def clamp(h):
    """Ed25519 clamping."""
    b = bytearray(h)
    b[0] &= 248
    b[31] &= 63
    b[31] |= 64
    clamped = bytes(b)
    print(f"    Clamped: {clamped.hex()}")
    return clamped

def scalar_mult_pubkey(scalar_bytes, pubkey_bytes):
    """Compute scalar * pubkey on Ed25519 curve."""
    # Ed25519 curve parameters
    p = 2**255 - 19
    d = -121665 * pow(121666, p-2, p) % p
    
    def mod_inv(x, mod=p):
        return pow(x, mod - 2, mod)
    
    def decompress_point(compressed):
        """Decompress Ed25519 point from 32 bytes."""
        y_bytes = bytearray(compressed)
        sign = (y_bytes[31] >> 7) & 1
        y_bytes[31] &= 0x7F
        y = int.from_bytes(y_bytes, 'little')
        
        # x^2 = (y^2 - 1) / (d * y^2 + 1)
        y2 = y * y % p
        x2 = (y2 - 1) * mod_inv(d * y2 + 1) % p
        
        # Square root
        x = pow(x2, (p + 3) // 8, p)
        if (x * x - x2) % p != 0:
            I = pow(2, (p - 1) // 4, p)
            x = x * I % p
        if (x * x - x2) % p != 0:
            return None
        
        if x % 2 != sign:
            x = p - x
        
        return (x, y)
    
    def point_add(P, Q):
        """Add two points on Ed25519."""
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        x3 = (x1*y2 + x2*y1) * mod_inv(1 + d*x1*x2*y1*y2) % p
        y3 = (y1*y2 + x1*x2) * mod_inv(1 - d*x1*x2*y1*y2) % p
        return (x3, y3)
    
    def point_double(P):
        return point_add(P, P)
    
    def scalar_mult(s, P):
        """Double-and-add scalar multiplication."""
        result = None  # point at infinity
        temp = P
        while s > 0:
            if s & 1:
                result = point_add(result, temp)
            temp = point_double(temp)
            s >>= 1
        return result
    
    def compress_point(P):
        """Compress Ed25519 point to 32 bytes."""
        x, y = P
        result = bytearray(y.to_bytes(32, 'little'))
        result[31] |= (x & 1) << 7
        return bytes(result)
    
    # Decompress the public key
    point = decompress_point(pubkey_bytes)
    if point is None:
        print("    ERROR: Failed to decompress public key")
        return None
    print(f"    Decompressed pubkey: x={point[0]}, y={point[1]}")
    
    # Interpret scalar as little-endian integer
    # For proper Ed25519 blinding, we use the clamped scalar directly
    # (matching Tor's expand256_modm with 32 bytes, which reduces mod l)
    l = 2**252 + 27742317777372353535851937790883648493
    scalar = int.from_bytes(scalar_bytes, 'little')
    scalar_mod_l = scalar % l
    print(f"    Scalar (raw): {scalar}")
    print(f"    Scalar (mod l): {scalar_mod_l}")
    
    # Multiply
    blinded = scalar_mult(scalar_mod_l, point)
    if blinded is None:
        print("    ERROR: scalar_mult returned None")
        return None
    
    result = compress_point(blinded)
    print(f"    Blinded pubkey: {result.hex()}")
    return result


def main():
    pubkey_hex = "ffb71d98e2be36bf10b720281d1b32105202cf70f69af6c128c402783721de08"
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    
    print("=" * 60)
    print("RustBalance Blinding Verification")
    print("=" * 60)
    print(f"Identity pubkey: {pubkey_hex}")
    
    # Get current time period
    current_tp, next_tp = compute_time_period()
    
    # Get Tor's blinded key
    print("\n--- Tor's descriptor info ---")
    get_tor_blinded_key()
    
    # Compute our blinding for current period
    print(f"\n--- Computing blinding for period {current_tp} ---")
    h = compute_blinding_factor(pubkey_bytes, current_tp, 1440)
    clamped = clamp(h)
    blinded = scalar_mult_pubkey(clamped, pubkey_bytes)
    
    # Also compute for next period
    print(f"\n--- Computing blinding for period {next_tp} ---")
    h2 = compute_blinding_factor(pubkey_bytes, next_tp, 1440)
    clamped2 = clamp(h2)
    blinded2 = scalar_mult_pubkey(clamped2, pubkey_bytes)
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Current period blinded key: {blinded.hex() if blinded else 'ERROR'}")
    print(f"Next period blinded key: {blinded2.hex() if blinded2 else 'ERROR'}")
    print("Compare these with Tor's blinded key from the descriptor above")


if __name__ == "__main__":
    main()
