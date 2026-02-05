#!/usr/bin/env python3
import hashlib
import time

# Test values from RustBalance
pubkey = bytes.fromhex("3bc09efcda967b643680765ff24c16b13a989ebc2a5bf9ff3a68b8db5142be71")

# Current time 
minutes_since_epoch = int(time.time() // 60)
rotation_offset = 720  # 12 hours in minutes
period_length = 1440  # 24 hours in minutes

period_num = (minutes_since_epoch - rotation_offset) // period_length
print(f"Current time period number: {period_num}")
print(f"RustBalance used period_num: 20487")
print(f"Match: {period_num == 20487}")
