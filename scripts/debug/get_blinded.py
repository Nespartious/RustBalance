#!/usr/bin/env python3
import socket
import base64

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 9051))

sock.send(b'AUTHENTICATE "rustbalance"\r\n')
resp = sock.recv(1024)
print(f'Auth: {resp}')

sock.send(b'GETINFO hs/client/desc/id/4m3tjcd2bue2xxzuodfjqombjnmbhyuyityf72x7ayeyth4m4yzr5nad\r\n')
resp = b''
while True:
    chunk = sock.recv(4096)
    resp += chunk
    if b'250 OK' in chunk or b'552' in chunk:
        break

lines = resp.decode('utf-8', errors='replace').split('\n')
for i, line in enumerate(lines):
    if 'descriptor-signing-key-cert' in line:
        print(f'Found cert at line {i}')
        cert_lines = []
        for j in range(i+1, min(i+10, len(lines))):
            l = lines[j].strip()
            if l.startswith('-----'):
                continue
            if 'revision-counter' in l or l == '':
                break
            cert_lines.append(l)
        cert_b64 = ''.join(cert_lines)
        print(f'Cert b64: {cert_b64[:60]}')
        cert_bytes = base64.b64decode(cert_b64)
        print(f'Cert hex: {cert_bytes.hex()}')
        blinded_key = cert_bytes[7:39]
        print(f'Blinded key: {blinded_key.hex()}')

sock.close()
