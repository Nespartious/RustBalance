#!/usr/bin/env python3
import socket
import sys

print("Starting...", flush=True)
s = socket.socket()
s.settimeout(10)
print("Connecting...", flush=True)
s.connect(('127.0.0.1', 9051))
print("Connected!", flush=True)

cookie = open('/run/tor/control.authcookie', 'rb').read()
cmd = b'AUTHENTICATE ' + cookie.hex().encode() + b'\r\n'
print(f"Auth cmd len: {len(cmd)}", flush=True)
s.send(cmd)
print(s.recv(1024), flush=True)

s.send(b'GETINFO hs/client/desc/id/exqtmxoxadp7q3ffmw3u224sn4yqek4i2ym2turapedoumkosdobvqyd\r\n')
data = s.recv(8192)
print(f"Response length: {len(data)}", flush=True)
print(data[:300], flush=True)
