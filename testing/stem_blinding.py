#!/usr/bin/env python3
"""Use stem's _blinded_pubkey to compute the CORRECT blinding and identify our bug."""
import hashlib
import struct
import time
import sys

def compute_time_period():
    now = int(time.time())
    minutes_since_epoch = now // 60
    adjusted = minutes_since_epoch - 720
    period_num = adjusted // 1440
    return period_num

# Try to use stem's internal blinding
try:
    from stem.descriptor.hidden_service import _blinded_pubkey, _blinded_sign
    HAVE_STEM = True
except ImportError:
    try:
        from stem.descriptor.hidden_service import HiddenServiceDescriptorV3
        import stem.descriptor.hidden_service as hs_mod
        _blinded_pubkey = getattr(hs_mod, '_blinded_pubkey', None)
        HAVE_STEM = _blinded_pubkey is not None
    except:
        HAVE_STEM = False

if HAVE_STEM:
    import inspect
    print("=== STEM _blinded_pubkey SOURCE ===")
    try:
        src = inspect.getsource(_blinded_pubkey)
        print(src[:3000])
        print("..." if len(src) > 3000 else "")
    except:
        print("Could not get source")
    
    print("\n=== STEM BLINDING COMPUTATION ===")
    pubkey_hex = "ffb71d98e2be36bf10b720281d1b32105202cf70f69af6c128c402783721de08"
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    tp = compute_time_period()
    
    # Try calling stem's blinding
    try:
        # stem._blinded_pubkey typically takes (identity_key, blinding_nonce)
        # Let's check its signature
        sig = inspect.signature(_blinded_pubkey)
        print(f"_blinded_pubkey signature: {sig}")
        
        # Try various calling conventions
        try:
            result = _blinded_pubkey(pubkey_bytes, tp)
            print(f"stem blinded key (pubkey, tp): {result.hex() if isinstance(result, bytes) else result}")
        except TypeError as e:
            print(f"Failed with (pubkey, tp): {e}")
            
        try:
            # Maybe it needs the nonce/param directly
            # Build the blinding nonce as Tor does
            nonce = b"key-blind" + struct.pack(">Q", tp) + struct.pack(">Q", 1440)
            result = _blinded_pubkey(pubkey_bytes, nonce)
            print(f"stem blinded key (pubkey, nonce): {result.hex() if isinstance(result, bytes) else result}")
        except TypeError as e:
            print(f"Failed with (pubkey, nonce): {e}")
            
    except Exception as e:
        print(f"Error calling _blinded_pubkey: {e}")
        import traceback
        traceback.print_exc()
else:
    print("stem._blinded_pubkey not available")
    
# Also look for any other blinding-related functions in stem
print("\n=== SEARCHING STEM FOR BLINDING CODE ===")
try:
    import stem.descriptor.hidden_service as hs_mod
    src = inspect.getsource(hs_mod)
    
    # Find all lines mentioning "blind"
    for i, line in enumerate(src.split('\n')):
        if 'blind' in line.lower() and ('def ' in line or 'BLIND' in line.upper() or 'blind_string' in line.lower() or 'sha3' in line.lower()):
            print(f"  Line {i+1}: {line.strip()[:120]}")
    
    # Find the _blinded_pubkey function and surrounding context
    lines = src.split('\n')
    for i, line in enumerate(lines):
        if 'def _blinded_pubkey' in line:
            # Print the function and some context
            start = max(0, i-2)
            end = min(len(lines), i+50)
            print(f"\n--- _blinded_pubkey at line {i+1} ---")
            for j in range(start, end):
                print(f"  {j+1}: {lines[j]}")
            break
    
    # Also find _blinded_sign
    for i, line in enumerate(lines):
        if 'def _blinded_sign' in line:
            start = max(0, i-2)
            end = min(len(lines), i+50)
            print(f"\n--- _blinded_sign at line {i+1} ---")
            for j in range(start, end):
                print(f"  {j+1}: {lines[j]}")
            break
    
    # Find BLIND_STRING
    for i, line in enumerate(lines):
        if 'BLIND_STRING' in line or 'blind_string' in line or 'Derive temporary' in line:
            print(f"\n  blind_string ref at line {i+1}: {line.strip()[:150]}")
            
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
