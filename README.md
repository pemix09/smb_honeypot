SMB Honeypot Proxy System
A transparent, logging-capable SMB proxy designed to sit in front of a vulnerable Samba instance. It captures all interactions, classifies traffic using heuristics, and stores metadata/payloads in a SQLite database for security analysis.

1. Architecture
The system is built using Docker and Python, focusing on the isolation of the vulnerable service:

Vulnerable SMB (vuln_smb): A Samba container running in an isolated Docker network (smb_net). It is not directly exposed to the host.

Honeypot Proxy (proxy): A custom Python asyncio application. It acts as the gatekeeper, intercepting all traffic, performing real-time heuristic analysis, and logging data to SQLite before forwarding it to the backend.

2. Prerequisites
Docker & Docker Compose

smbclient: Required for running the verification scripts (usually available via brew install samba on macOS or apt install smbclient on Linux).

Python 3.11+: For executing the local check script.

3. Installation & Startup
Port Configuration: On macOS, the system often reserves port 445. If you encounter "Address already in use" errors, modify the ports mapping in docker-compose.yml for the proxy service to use an alternative external port:

YAML

ports:
  - "4445:445" # External 4445 -> Internal 445
Start the containers:

Bash

docker compose up -d --build
4. Verification
To verify that the proxy is correctly capturing and forwarding traffic, run the provided simulation script:

Bash

# Usage: ./scripts/check_flag.py <IP> --port <PORT>
./scripts/check_flag.py 127.0.0.1 --port 445
The script will:

Connect to the SMB share via the proxy.

Download the FLAG.txt file.

Query the honeypot.db and display the captured logs directly in your terminal.

5. Security & Logging Features
Asynchronous Logging: Uses an internal asyncio.Queue and a background worker to ensure that database I/O operations do not introduce latency in the SMB stream, preventing session timeouts.

Protocol Classification: The proxy identifies the dialect being used (e.g., Legacy SMBv1 vs. Modern SMB2/3) and logs it in the classification field.

Raw Payload Capture: All packets are Base64 encoded and stored in the raw column, allowing for post-incident deep packet inspection (DPI).

Robustness: The proxy is designed with wide try-except blocks to handle malformed packets or unsupported dialects without crashing the service.

6. Database Schema
The SQLite database (data/honeypot.db) follows this structure:

timestamp: UTC event time.

src_ip / src_port: Attacker identification.

event_type: Category of event (connection_open, data_c2s, data_s2c, etc.).

raw: The Base64 encoded packet.

classification: Heuristic label (e.g., flag_access_attempt, smb2_3_traffic).

details: JSON metadata (packet size, detected filenames, etc.).