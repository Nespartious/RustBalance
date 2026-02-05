#!/usr/bin/env python3
"""
Capture the full descriptor from the Tor cache and analyze it
"""

from stem.control import Controller

ctrl = Controller.from_port(port=9051)
ctrl.authenticate()

# Get the master descriptor that Tor has cached
addr = "gc5itylvnbe5x2pbcrwtmsah3hulmpthtwyg3zvbfii4b2kmplgtroad"
try:
    resp = ctrl.get_info(f"hs/client/desc/id/{addr}")
    
    # Save to file for analysis
    with open("/tmp/master_descriptor.txt", "w") as f:
        f.write(resp)
    
    print(f"Saved descriptor ({len(resp)} bytes) to /tmp/master_descriptor.txt")
    
    # Parse and display structure
    print("\n=== Descriptor Structure ===")
    lines = resp.split("\n")
    for i, line in enumerate(lines):
        if line.startswith(("hs-descriptor", "descriptor-lifetime", "descriptor-signing-key-cert", 
                           "revision-counter", "superencrypted", "signature", "-----")):
            print(f"{i}: {line[:80]}")
    
except Exception as e:
    print(f"Error: {e}")

ctrl.close()
