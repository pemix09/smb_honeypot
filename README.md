🍯 SMB Chaos Honeypot

This project is an intelligent Honeypot mimicking the SMB (Server Message Block) service. It is written in Rust for performance and safety, while data analysis is handled by a Python script.

Key Features:

Active Deception: Not only does it log activity, but it also actively "responds" with random data (Chaos Response) to confuse scanners like Nmap or Metasploit.

Deep Inspection: Recognizes protocol versions (SMBv1/v2/v3) and specific attack types (e.g., EternalBlue, login attempts, share enumeration).

SQLite & CSV: Logs are stored in a lightweight database and can be exported to a readable CSV file.

Dockerized: The entire system runs in isolated containers.

🚀 1. Deployment

Ensure you have Docker and Docker Compose installed.

Step A: Build and Start the Server

Run the following command in the main project directory. This will build the Rust image and start the honeypot in the background.

docker compose up -d --build honeypot


What happens? The server listens on port 445.

Where is the data? A honeypot.db file will be created in the data/ folder.

Step B: Check Status

To verify if the honeypot is running and to view live logs:

docker compose logs -f honeypot


⚔️ 2. How to Attack (Simulation)

The honeypot works best when someone tries to scan it. Here is how you can generate traffic to test the system. Use another computer or a second terminal window.

Method 1: Nmap (Best for testing)

Nmap is the standard tool for network scanning.

Quick Version Scan:

nmap -p 445 -sV <HONEYPOT_IP>


SMB Script Scanning (Reconnaissance Simulation):
This will generate many logs like NEGOTIATE, SESSION_SETUP, or TREE_CONNECT.

nmap -p 445 --script smb-protocols <HONEYPOT_IP>


Aggressive Scan (OS Detection):

nmap -A -p 445 <HONEYPOT_IP>


Method 2: Metasploit (Advanced)

If you have the Metasploit Framework, you can try scanning modules:

msfconsole
use auxiliary/scanner/smb/smb_version
set RHOSTS <HONEYPOT_IP>
run


Method 3: Netcat (Manual Connection)

To simply check if the port is open and receive a "Chaos Response":

nc <HONEYPOT_IP> 445


(You should see a connection successful message, followed by strange characters/garbage data sent by the server).

📊 3. Generating Dataset (CSV)

The honeypot saves data to the SQLite database in real-time. To export it to CSV format for analysis (e.g., in Excel or Pandas):

Run the exporter container once:

docker compose run --rm exporter


Result:
A new file dataset.csv will be created in the data/ folder containing all captured logs.