🍯 SMB Chaos Honeypot (Medium Interaction)

An intelligent, deceptive SMB honeypot built with Rust and Python. This version features "Medium Interaction" capabilities, meaning it actively tricks attackers into believing they have accessed network shares while logging their specific intents.

🚀 1. Key Features

Active Deception (Chaos Mode): Responds with structured NetBIOS frames containing random junk data to confuse automated scanners.

Medium Interaction:

Path Extraction: Automatically parses and logs the specific network paths (e.g., \\192.168.1.1\C$) that attackers try to access.

Fake Tree Success: When an attacker attempts a TREE_CONNECT, the honeypot sends a "Success" response, encouraging the attacker to proceed with further commands.

Deep Inspection: Recognizes SMBv1 and SMBv2/v3 protocols and logs specific commands (Negotiate, Session Setup, Tree Connect, Create/Open, etc.).

Persistent Storage: All events are saved in a SQLite database (honeypot.db) within a persistent Docker volume.

One-Click Export: A Python script instantly converts the database into a dataset.csv for analysis.

🛠️ 2. Simulated Commands

Below are the SMB operations currently handled by the honeypot:

- SMBv1 - NEGOTIATE - Initial protocol handshake.
- SMBv1 - TREE_CONNECT_ANDX - Attempting to map a network drive (Paths are captured!). The "AndX" suffix stands for "And Then". In the old SMBv1 protocol, this was a way to chain multiple commands into a single request to save network round-trips. For example, a client could send a request to "Connect to this share AND THEN open this specific file" in one go.
- SMBv1 - NT_TRANSACT_SECONDARY - NT_TRANSACT_SECONDARY (or SMB_COM_NT_TRANSACT_SECONDARY) is an old SMB (Server Message Block) command (code 0xA1) used in Windows networking for complex, extended transactions, allowing the client and server to exchange larger data or perform multiple operations within a single connection, acting as a continuation or secondary part to an initial NT_TRANSACT request (code 0xA0), often seen in older protocols like SMBv1 for file system operations or printer jobs Potential EternalBlue (WannaCry) exploit attempt.
- SMBv2/3 - NEGOTIATE - Modern protocol handshake.
- SMBv2/3 - SESSION_SETUP - In the SMB protocol, SESSION_SETUP is the phase where the "handshake" moves from technical negotiation to user authentication. It is the step where a client (attacker or user) attempts to log in to the server. Follows the NEGOTIATE phase.
- SMBv2/3 - TREE_CONNECT - TREE_CONNECT is a fundamental command in the SMB protocol. It represents the moment an attacker (or a legitimate user) attempts to "enter" or "mount" a specific resource on the server.
- SMBv2/3 - CREATE_FILE/OPEN - Attempting to read or write a specific file. It is the critical point where an user or attacker attempts to interact with a specific object—usually a file or a directory—after they have successfully connected to a share.
- Any - CHAOS - Randomized response for all other unhandled commands.

📦 3. Deployment

Start the Honeypot

Run this in the project root to build and start the server:

docker compose up -d --build honeypot


Monitor Live Logs

docker compose logs -f honeypot


⚔️ 4. Simulating Attacks

Test the honeypot using these common security tools:

Nmap Share Enumeration:

nmap -p 445 --script smb-enum-shares <HONEYPOT_IP>


Protocol Scanning:

nmap -p 445 --script smb-protocols <HONEYPOT_IP>


Manual Connection (Windows/Linux):
Try to map a drive to see it logged:

net use X: \\<HONEYPOT_IP>\SensitiveData


📊 5. Data Management

Database Location

The SQLite database is located at: data/honeypot.db. It persists even if containers are restarted.

Exporting to CSV

To generate the dataset.csv file in the data/ folder, run:

docker compose run --rm exporter


Database Schema

The captured dataset includes:

timestamp: When the event occurred.

src_ip: Attacker's IP and port.

protocol_ver: SMBv1 or SMBv2/3.

command_name: The specific operation performed.

metadata: Extracted paths or extra info from the payload.

raw_payload_hex: Full hex dump of the received packet.

Database / inspection
---------------------

The honeypot stores all events in SQLite at: `data/honeypot.db` (persisted via Docker volume).

Files added to help inspection:

- `schema.sql` — SQL schema for the `logs` and `daily_summary` tables.
- `scripts/db_inspector.py` — small Python script that prints last N logs, counts by classification and daily summaries.

Quick ways to inspect the database:

- Using the included inspector script (recommended):

```bash
python3 scripts/db_inspector.py --db ./data/honeypot.db --last 25
```

- Using `sqlite3` CLI:

```bash
sqlite3 ./data/honeypot.db
.schema
SELECT id,timestamp,src_ip,src_port,dst_port,protocol,event_type,classification FROM logs ORDER BY id DESC LIMIT 20;
SELECT * FROM daily_summary;
```

Run the inspector inside Docker (no local Python deps):

```bash
docker run --rm -v "$(pwd)/data:/app/data" -v "$(pwd)/scripts:/app/scripts" python:3.11-slim python /app/scripts/db_inspector.py --db /app/data/honeypot.db --last 25
```

If you want to regenerate the `schema.sql` structure used by the running honeypot, you can run:

```bash
sqlite3 ./data/honeypot.db ".schema" > current_schema.sql
```

Supported SMB interactions
--------------------------

The honeypot supports (and logs) several common SMB interaction types. These are intentionally simple emulations but are sufficient for training/analysis and for capturing attacker behavior.

- Connect / Negotiate: client opens a TCP connection to port 445 — logged as `connection`.
- Session setup / auth attempts: attempts to authenticate (logged as `auth_attempt`).
- Tree connect (enter share / directory): logged as `file_operation` with `parsed` containing `TREE_CONNECT` and `metadata` (if a path was extractable).
- List directory (`ls` / enumerate): emulated as data requests after `TREE_CONNECT` — logged as `file_operation` / `data`.
- Change directory (`cd`): emulated via `TREE_CONNECT` to a different path — logged as `file_operation`.
- Create / upload file (`put`): emulated with `CREATE/WRITE` frames — logged as `file_operation` (raw payload contains file content in base64).
- Delete file: emulated by specific write-like deletions (logged as `file_operation`).

Examples (how to exercise interactions):

- Using `smbclient` (if available):

```bash
# list shares
smbclient -L //HONEYPOT_IP -N

# connect and upload
smbclient //HONEYPOT_IP/Share -N -c "ls; cd uploads; put ./localfile.txt remotefile.txt; exit"
```

- Using the provided simulation scripts (no smbclient required):

```bash
python3 scripts/simulate_interactions.py   # runs ls, cd, put x3, delete
python3 scripts/generate_strong_traffic.py # more aggressive tests (auth bursts, sqli, cmd inj, php uploads)
```

Where interactions appear in the DB
---------------------------------

- `event_type`: will be `connection`, `auth_attempt`, `file_operation`, or `data`.
- `parsed`: contains normalized fields such as `protocol`, `command` and `metadata` (extracted path).
- `raw`: base64 of the raw payload (useful to reconstruct exact bytes or extract filenames/contents).

Sample SQL to view file activity:

```sql
SELECT id,timestamp,src_ip,event_type,parsed,classification,details
FROM logs
WHERE event_type='file_operation' OR parsed LIKE '%TREE_CONNECT%'
ORDER BY id DESC LIMIT 50;
```

If you'd like, I can also add example `smbclient` commands run from within a small helper container (we already used an ephemeral container during testing) and include their exact outputs in the repository documentation.