# SMB Honeypot Proxy (Docker Compose Edition)

This project demonstrates an Asynchronous **Man-in-the-Middle (MITM) Honeypot Proxy** for the SMB protocol. It intercepts traffic, classifies attacks using packets analysis, and logs events to an SQLite database.

## Architecture

The system is containerized using **Docker Compose**:
1.  **`proxy`**: The Python Asyncio Proxy (Port 445).
2.  **`vuln_smba`**: A simulation of a vulnerable server (Internal network). The docker image used: dperson/samba:latest - https://hub.docker.com/layers/dperson/samba/latest/images/sha256-e1d2a7366690749a7be06f72bdbf6a5a7d15726fc84e4e4f41e967214516edfd - samba in version 4.13.7

---

## Step 1: Deployment

### 1. Build and Start
Run the following command in the project directory:

```
docker compose up --build -d
```
--build: Rebuilds the Python image.
-d: Runs containers in the background (detached mode).

### 2. Verify Status
Check if both containers are running:

```
docker compose ps
```
Status should be Up for both smb_honeypot and vuln_target.

### 3. View Real-time Logs
To see the proxy starting up and processing connections:

real time proxy logs: 
```
docker compose logs -f proxy
```

real time vulnerable smb service logs:
```
docker compose logs -f vuln_smb
```

Sample usage:

Scenario A: SQL Injection Attack 

detection in <b>analyze_traffic</b> function

Attacker Action: Send a payload containing SQL keywords.

```
echo "admin' UNION SELECT 1, password FROM users --" | nc localhost 445
```

Verification: Check the logs inside the Docker container:

```
docker exec smb_proxy sqlite3 /app/data/honeypot.db \
"SELECT timestamp, event_type, classification FROM logs WHERE classification='sql_injection' ORDER BY id DESC LIMIT 1;"
```

Expected Result: Classification: sql_injection

Scenario B: Remote Code Execution (RCE)

detection in <b>analyze_traffic</b> function

Attacker Action: Attempt to execute a shell command via the stream.

```
echo "GET /index.php?cmd=/bin/sh HTTP/1.1" | nc localhost 445
```

Verification:

```
docker exec smb_proxy sqlite3 /app/data/honeypot.db \
"SELECT timestamp, classification, details FROM logs WHERE classification='command_injection' ORDER BY id DESC LIMIT 1;"
```

Expected Result: Classification: command_injection

Scenario C: Port Scanning

detection in code in <b>update_connection_metrics</b>

Attacker Action: Rapidly open and close connections

```
for i in {1..25}; do nc -z localhost 445; done
```

Verification:

```
docker exec smb_proxy sqlite3 /app/data/honeypot.db \
"SELECT timestamp, src_ip, classification, details FROM logs WHERE classification='scanning' ORDER BY id DESC LIMIT 1;"
```

Expected Result: Classification: scanning

Step 3: Inspecting the Database
Since Docker maps the ./data volume, the database is persisted. 

Check Traffic Flow (clientToServer vs serverToClient):

```
docker exec smb_proxy sqlite3 -column -header /app/data/honeypot.db \
"SELECT event_type, count(*) as count FROM logs GROUP BY event_type;"
```

Step 4: Cleanup
To stop and remove the containers:

```
docker compose down
```