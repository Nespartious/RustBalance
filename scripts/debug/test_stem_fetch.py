#!/usr/bin/env python3
"""
Use stem to fetch and decrypt our backend HS descriptor.
This will verify if the descriptor is valid and can be decrypted.
"""

import os
import sys

try:
    import stem
    from stem.descriptor.hidden_service import HiddenServiceDescriptorV3
    from stem.descriptor.certificate import Ed25519CertificateV1
    print(f"stem version: {stem.__version__}")
except ImportError:
    print("ERROR: stem not installed. Run: pip install stem")
    sys.exit(1)

# Our backend HS onion address
ONION_ADDRESS = "esnymppkuwdhwam6vzthfvtl2i2y64rwwyt23gp63xmctndqp5tvgaad.onion"

def analyze_descriptor(descriptor_text: str, onion_address: str):
    """Parse and analyze a descriptor"""
    print("\n=== Analyzing Descriptor ===")
    
    try:
        desc = HiddenServiceDescriptorV3.from_str(descriptor_text)
        print(f"Descriptor version: {desc.version}")
        print(f"Revision counter: {desc.revision_counter}")
        print(f"Lifetime: {desc.lifetime} minutes")
        print(f"Has signing_cert: {desc.signing_cert is not None}")
        
        if desc.signing_cert:
            blinded_key = desc.signing_cert.signing_key()
            if blinded_key:
                print(f"Blinded key from cert: {blinded_key.hex()}")
                print(f"  Expected: 35583b72129f59ed130df845d1b45eabfe9b013817e9fef1d37a9544da1896b0")
            else:
                print("WARNING: No signing key in certificate extensions!")
        
        # Try to decrypt
        print("\nAttempting decryption...")
        try:
            desc.decrypt(onion_address)
            print("SUCCESS: Descriptor decrypted!")
            
            # Check intro points
            if hasattr(desc, 'introduction_points') and desc.introduction_points():
                intro_points = desc.introduction_points()
                print(f"Found {len(intro_points)} introduction points")
                for i, ip in enumerate(intro_points):
                    print(f"  IP {i}: {ip}")
        except Exception as e:
            print(f"DECRYPTION FAILED: {e}")
            import traceback
            traceback.print_exc()
            
    except Exception as e:
        print(f"PARSING FAILED: {e}")
        import traceback
        traceback.print_exc()

def main():
    # Read descriptor from file if provided
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            descriptor_text = f.read()
        analyze_descriptor(descriptor_text, ONION_ADDRESS)
        return
    
    # Otherwise, we need to have a saved descriptor
    print("Usage: python test_stem_fetch.py <descriptor_file>")
    print("Or provide descriptor text via stdin")

if __name__ == "__main__":
    main()
