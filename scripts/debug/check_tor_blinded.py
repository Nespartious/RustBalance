#!/usr/bin/env python3
"""
Check what blinded key Tor would compute for our master address
by uploading and capturing the HS_DESC event
"""

from stem.control import Controller, EventType
import time
import threading

# Connect to Tor
ctrl = Controller.from_port(port=9051)
ctrl.authenticate()

# Listen for HS_DESC events to see what index/descriptor_id is used
events = []

def hs_desc_handler(event):
    events.append(event)
    print(f"HS_DESC: action={event.action}, address={event.address}")
    if hasattr(event, 'descriptor_id') and event.descriptor_id:
        print(f"  descriptor_id={event.descriptor_id}")
    if hasattr(event, 'reason') and event.reason:
        print(f"  reason={event.reason}")
    if hasattr(event, 'index') and event.index:
        print(f"  index={event.index}")

ctrl.add_event_listener(hs_desc_handler, EventType.HS_DESC)

# Give it a moment to register
time.sleep(1)

# Now let's query what descriptor Tor has cached for our address
addr = "gc5itylvnbe5x2pbcrwtmsah3hulmpthtwyg3zvbfii4b2kmplgtroad"

print(f"\nQuerying cached descriptor for {addr}...")

try:
    desc = ctrl.get_info(f"hs/client/desc/id/{addr}")
    print(f"Got descriptor: {len(desc)} bytes")
    
    # Extract and show the cert from the descriptor
    lines = desc.split("\n")
    in_cert = False
    cert_lines = []
    for line in lines:
        if line == "-----BEGIN ED25519 CERT-----":
            in_cert = True
            continue
        if line == "-----END ED25519 CERT-----":
            in_cert = False
            break
        if in_cert:
            cert_lines.append(line)
    
    if cert_lines:
        import base64
        cert_b64 = "".join(cert_lines)
        cert = base64.b64decode(cert_b64)
        print(f"\nCert bytes ({len(cert)}): {cert.hex()}")
        
        # Extract blinded key from extension
        # After cert[40] starts the extension: 2 bytes len, 1 byte type, 1 byte flags, 32 bytes data
        if len(cert) >= 76:
            ext_data = cert[44:76]
            print(f"Blinded key in cached cert: {ext_data.hex()}")
            
except Exception as e:
    print(f"Error getting descriptor: {e}")

# Wait a moment for any pending events
time.sleep(2)

print(f"\n{len(events)} HS_DESC events captured")

ctrl.close()
