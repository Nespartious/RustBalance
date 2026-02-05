#!/usr/bin/env python3
import socket
import select
import time

with open("/run/tor/control.authcookie", "rb") as f:
    cookie = f.read()

sock = socket.socket()
sock.connect(("127.0.0.1", 9051))
sock.settimeout(5)

sock.send(("AUTHENTICATE " + cookie.hex() + "\r\n").encode())
print(sock.recv(1024).decode().strip())

sock.send(b"SETEVENTS HS_DESC\r\n")
print(sock.recv(1024).decode().strip())

print("Waiting for HS_DESC events...")
sock.setblocking(False)
start = time.time()
while time.time() - start < 120:
    try:
        r, _, _ = select.select([sock], [], [], 1.0)
        if r:
            data = sock.recv(8192).decode()
            for line in data.strip().split("\n"):
                if line.startswith("650"):
                    print(line)
    except:
        pass
