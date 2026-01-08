#!/usr/bin/env python3
"""
Generate stronger SMB-like test traffic to trigger classification rules:
 - brute_force: many SESSION_SETUP (SMBv2) within short time
 - sql_injection: payload containing SQL patterns
 - command_injection: payload with shell tokens
 - file_upload_malicious: SMBv1 TREE_CONNECT with .php path
 - binary MZ payload
"""
import socket
import time

HOST = '127.0.0.1'
PORT = 445

def netbios_wrap(body: bytes) -> bytes:
    length = len(body)
    nb = bytes([0x00]) + length.to_bytes(3, 'big')
    return nb + body

# SMBv2 packet builder that sets command at offset 12-13
def smb_v2_session_setup(payload: bytes = b'') -> bytes:
    # build minimal SMB2 header: 0xFE 'SMB' + 64-byte header (we'll place command at bytes 12-13)
    header = bytes([0xFE]) + b'SMB' + bytearray(64)
    # set command (u16 little endian) at offset 12
    cmd = (0x0001).to_bytes(2, 'little')
    header = header[:4] + header[4:12] + cmd + header[14:]
    return netbios_wrap(header + payload)

# SMBv1 TREE_CONNECT with path placed at offset 32
def smb_v1_tree_connect(path: str) -> bytes:
    smb_header = bytes([0xFF]) + b'SMB' + bytes([0x75])
    # pad to 32 bytes after header
    pad_len = 32 - len(smb_header)
    pad = b'\x00' * pad_len
    path_bytes = path.encode('utf-8') + b'\x00'
    body = smb_header + pad + path_bytes
    return netbios_wrap(body)

# Generic sender
def send_packet(data: bytes, wait: float = 0.02):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((HOST, PORT))
        s.sendall(data)
        try:
            s.recv(1024)
        except Exception:
            pass
        s.close()
    except Exception as e:
        print('send error:', e)
    time.sleep(wait)

if __name__ == '__main__':
    print('Sending strong test traffic to', HOST, PORT)

    # 1) brute_force: rapid SESSION_SETUP (SMBv2)
    for i in range(12):
        payload = f"username=admin{i}&password=wrong{i}".encode()
        pkt = smb_v2_session_setup(payload)
        send_packet(pkt, wait=0.25)
    print('-> brute_force-like SESSION_SETUP burst sent (12)')

    # 2) sql_injection: send a packet with SQL pattern
    sqli = b"GET /vuln?id=1 OR 1=1 HTTP/1.1\r\nHost: target\r\n\r\n"
    pkt = smb_v2_session_setup(sqli)
    send_packet(pkt)
    print('-> SQLi payload sent')

    # 3) command_injection: shell tokens
    cmd = b"POST /cmd HTTP/1.1\r\nHost: target\r\n\r\ncmd=uname -a; ls -la /tmp && bash -i\n"
    pkt = smb_v2_session_setup(cmd)
    send_packet(pkt)
    print('-> Command injection payload sent')

    # 4) file upload malicious: SMBv1 TREE_CONNECT with .php path
    pkt = smb_v1_tree_connect('\\\\10.0.0.1\\uploads\\shell.php')
    send_packet(pkt)
    print('-> SMBv1 TREE_CONNECT with .php path sent')

    # 5) Binary MZ payload (large)
    mz = b'MZ' + b'\x90' * 1024
    pkt = netbios_wrap(bytes([0xFF]) + b'SMB' + bytes([0xA2]) + b'\x00'*32 + mz)
    send_packet(pkt)
    print('-> Large MZ payload sent')

    print('Strong traffic generation complete')
