#!/usr/bin/env python3
"""
Listen for HS_DESC events and capture more details
"""

from stem.control import Controller, EventType
import sys
import time

ctrl = Controller.from_port(port=9051)
ctrl.authenticate()

print("Listening for HS_DESC events...")
print("Press Ctrl+C to stop\n")

def hs_desc_handler(event):
    print(f"[{time.strftime('%H:%M:%S')}] HS_DESC event:")
    print(f"  Action: {event.action}")
    print(f"  Address: {event.address}")
    if hasattr(event, 'authentication'):
        print(f"  Auth: {event.authentication}")
    if hasattr(event, 'directory'):
        print(f"  Directory: {event.directory}")
    if hasattr(event, 'descriptor_id'):
        print(f"  Descriptor ID: {event.descriptor_id}")
    if hasattr(event, 'reason'):
        print(f"  Reason: {event.reason}")
    if hasattr(event, 'replica'):
        print(f"  Replica: {event.replica}")
    if hasattr(event, 'index'):
        print(f"  Index: {event.index}")
    print()

ctrl.add_event_listener(hs_desc_handler, EventType.HS_DESC)

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nStopped")

ctrl.close()
