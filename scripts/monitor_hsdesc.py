#!/usr/bin/env python3
"""Monitor Tor control port for HS_DESC events"""
import socket
import os

# Read auth cookie
with open('/run/tor/control.authcookie', 'rb') as f:
    cookie = f.read()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 9051))
sock.settimeout(60)

# Authenticate
auth_cmd = f"AUTHENTICATE {cookie.hex()}\r\n"
sock.send(auth_cmd.encode())
response = sock.recv(1024).decode()
print(f"Auth: {response.strip()}")

# Subscribe to HS_DESC events
sock.send(b"SETEVENTS HS_DESC\r\n")
response = sock.recv(1024).decode()
print(f"SetEvents: {response.strip()}")

print("Monitoring for HS_DESC events (60s)...")

# Read events
import time
start = time.time()
while time.time() - start < 60:
    try:
        data = sock.recv(4096).decode()
        if data:
            for line in data.split('\r\n'):
                if 'gc5itylvnbe' in line or 'HS_DESC' in line:
                    print(line)
    except socket.timeout:
        break

sock.close()
