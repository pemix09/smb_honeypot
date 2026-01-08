#!/usr/bin/env python3
"""
Simulate common SMB interactions: list (ls), change dir (cd), create files (put), delete.
This uses simple SMBv1 frames (Tree Connect / Write) to emulate activity that the honeypot logs.
"""
import socket
import time

HOST = '127.0.0.1'
PORT = 445

def netbios_wrap(body: bytes) -> bytes:
    length = len(body)
    return bytes([0x00]) + length.to_bytes(3, 'big') + body

# SMBv1 helper: build frame with command byte and payload
def smb_v1(cmd_byte: int, payload: bytes = b'') -> bytes:
    header = bytes([0xFF]) + b'SMB' + bytes([cmd_byte])
    return netbios_wrap(header + payload)

# Emulate ls: send TREE_CONNECT then a FIND/TRANS2-like payload (we just send data)
def do_ls(s):
    pkt = smb_v1(0x75, b'\x00'*32 + b'LS_COMMAND')
    s.sendall(pkt)
    time.sleep(0.05)

# Emulate cd: send TREE_CONNECT with target path
def do_cd(s, path: str):
    pathb = path.encode('utf-8') + b'\x00'
    pkt = smb_v1(0x75, b'\x00'*32 + pathb)
    s.sendall(pkt)
    time.sleep(0.05)

# Emulate create/put: send CREATE/WRITE payloads
def do_put(s, filename: str, content: bytes):
    pathb = filename.encode('utf-8') + b'\x00'
    pkt1 = smb_v1(0x75, b'\x00'*32 + pathb)
    s.sendall(pkt1)
    time.sleep(0.05)
    pkt2 = smb_v1(0x2E, content)
    s.sendall(pkt2)
    time.sleep(0.05)

# Emulate delete: send CREATE_FILE with delete token (we send a marker)
def do_delete(s, filename: str):
    pkt = smb_v1(0x2E, b'DELETE:' + filename.encode())
    s.sendall(pkt)
    time.sleep(0.05)

if __name__ == '__main__':
    print('Simulating interactions against', HOST, PORT)
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((HOST, PORT))

        do_ls(s)
        print('-> ls simulated')

        do_cd(s, '\\\\127.0.0.1\\uploads')
        print('-> cd uploads simulated')

        for i in range(3):
            fname = f'fakefile_{i}.txt'
            do_put(s, '\\\\127.0.0.1\\uploads\\' + fname, f'content {i}\n'.encode())
            print(f'-> put {fname}')

        do_delete(s, '\\\\127.0.0.1\\uploads\\fakefile_1.txt')
        print('-> delete fakefile_1.txt simulated')

        s.close()
        print('Simulations complete')
    except Exception as e:
        print('error', e)
