use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use chrono::{DateTime, Utc};
use rand::Rng;
use rusqlite::{params, Connection};
use std::collections::HashMap;
use base64;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::json;

// Database path inside the Docker container
const DB_PATH: &str = "data/honeypot.db";
const DST_PORT: i64 = 445;

// Structure holding the analyzed SMB packet data
struct ParsedSmb {
    protocol: String,    // e.g., SMBv1, SMBv2/3
    command: String,     // e.g., NEGOTIATE, TREE_CONNECT, NT_TRANSACT
    is_negotiate: u8,    // 1 if it is a negotiation, 0 otherwise
    metadata: String,    // Additional info, e.g., network share path
}

// Shared state used for simple heuristics across connections
struct SharedState {
    // auth attempts timestamps per src_ip
    auth_attempts: HashMap<String, Vec<DateTime<Utc>>>,
    // list of recent distinct commands per src_ip (timestamp, command)
    commands_seen: HashMap<String, Vec<(DateTime<Utc>, String)>>,
}

impl SharedState {
    fn new() -> Self {
        SharedState {
            auth_attempts: HashMap::new(),
            commands_seen: HashMap::new(),
        }
    }
}

fn main() -> std::io::Result<()> {
    // Short delay to allow the Docker filesystem to initialize
    std::thread::sleep(std::time::Duration::from_secs(2));

    println!("🚀 SMB Honeypot [Medium Interaction] starting...");
    
    // SQLite database initialization
    if let Err(e) = init_db(DB_PATH) {
        eprintln!("❌ Database initialization error: {}", e);
    } else {
        println!("📂 Database connected: {}", DB_PATH);
    }

    // Listening on standard SMB port 445
    let listener = TcpListener::bind("0.0.0.0:445")?;
    println!("👂 Listening on port 445. Waiting for connections...");

    // Global ID counter for console logs
    let global_id = Arc::new(Mutex::new(0u64));

    // Shared heuristics state
    let shared = Arc::new(Mutex::new(SharedState::new()));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let id_counter = Arc::clone(&global_id);
                let s_clone = Arc::clone(&shared);
                // Handle each connection in a separate thread
                std::thread::spawn(move || {
                    handle_client(stream, id_counter, s_clone);
                });
            }
            Err(e) => eprintln!("❌ TCP connection error: {}", e),
        }
    }
    Ok(())
}

fn handle_client(mut stream: TcpStream, id_counter: Arc<Mutex<u64>>, shared: Arc<Mutex<SharedState>>) {
    let mut buffer = [0; 8192];
    let peer = stream.peer_addr();
    let src_ip = peer.as_ref().map(|a| a.ip().to_string()).unwrap_or_else(|_| "UNKNOWN".to_string());
    let src_port = peer.as_ref().map(|a| a.port()).unwrap_or(0);

    // Loop handling multiple packets in one session (needed for exploits, for example)
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break, // Connection closed by client
            Ok(size) => {
                let mut id = id_counter.lock().unwrap();
                *id += 1;
                let current_id = *id;
                drop(id);

                let raw_data = &buffer[0..size];

                // --- ANALYSIS ---
                let analysis = parse_smb_packet(raw_data);

                // Determine event_type
                let event_type = if analysis.is_negotiate == 1 {
                    "connection".to_string()
                } else if analysis.command.contains("SESSION_SETUP") {
                    "auth_attempt".to_string()
                } else if analysis.command.contains("TREE_CONNECT") || analysis.command.contains("CREATE_FILE") {
                    "file_operation".to_string()
                } else {
                    "data".to_string()
                };

                // --- CLASSIFICATION ---
                let (classification, confidence, details) = classify_event(&analysis, raw_data, &src_ip, event_type.as_str(), Arc::clone(&shared));

                // --- SQLITE LOGGING ---
                if let Err(e) = insert_log_record(&src_ip, src_port as i64, DST_PORT, "SMB", &event_type, raw_data, &analysis, &classification, confidence, &details) {
                    eprintln!("❌ Database write error: {}", e);
                }

                // Log the event to the console
                println!("[#{}] {}:{} | {} | {} | class={} ({:.2}) | meta={}", 
                    current_id, src_ip, src_port, analysis.protocol, analysis.command, classification, confidence, analysis.metadata);

                // --- RESPONSE (ACTIVE DECEPTION) ---
                if analysis.command.contains("TREE_CONNECT") {
                    // If the attacker tries to enter a folder, pretend it succeeded
                    send_fake_success_response(&mut stream);
                } else {
                    // Otherwise, send a random "Chaos Response"
                    send_chaos_response(&mut stream);
                }
            }
            Err(_) => break, // Read error, terminating thread
        }
    }
}

fn parse_smb_packet(payload: &[u8]) -> ParsedSmb {
    let mut info = ParsedSmb {
        protocol: "UNKNOWN".to_string(),
        command: "UNKNOWN".to_string(),
        is_negotiate: 0,
        metadata: "-".to_string(),
    };

    if payload.len() < 8 { return info; }

    // NetBIOS header handling (first 4 bytes)
    let mut offset = 0;
    if payload[0] == 0x00 && payload.len() > 4 {
        // Check if SMB magic is at offset 4
        if payload[4] == 0xFF || payload[4] == 0xFE {
            offset = 4;
        }
    }
    let smb_data = &payload[offset..];

    // SMBv1 detection (\\xFFSMB)
    if smb_data.len() > 4 && smb_data[0] == 0xFF && &smb_data[1..4] == b"SMB" {
        info.protocol = "SMBv1".to_string();
        if smb_data.len() > 5 {
            let cmd = smb_data[4];
            info.command = match cmd {
                0x72 => { info.is_negotiate = 1; "NEGOTIATE".to_string() },
                0x75 => {
                    // Attempt to extract the path (e.g., \\\\192.168.1.1\\C$)
                    info.metadata = extract_ascii_path(&smb_data[32..]);
                    "TREE_CONNECT_ANDX".to_string()
                },
                0xA2 => "NT_TRANSACT_SECONDARY (EternalBlue?)".to_string(),
                0x2E => "WRITE_ANDX".to_string(),
                _ => format!("SMB1_CMD_0x{:02X}", cmd),
            };
        }
    } 
    // SMBv2/v3 detection (\\xFESMB)
    else if smb_data.len() > 4 && smb_data[0] == 0xFE && &smb_data[1..4] == b"SMB" {
        info.protocol = "SMBv2/3".to_string();
        if smb_data.len() > 14 {
            let cmd = u16::from_le_bytes([smb_data[12], smb_data[13]]);
            info.command = match cmd {
                0x0000 => { info.is_negotiate = 1; "NEGOTIATE".to_string() },
                0x0001 => "SESSION_SETUP".to_string(),
                0x0003 => "TREE_CONNECT (Share Access)".to_string(),
                0x0005 => "CREATE_FILE/OPEN".to_string(),
                0x000B => "IOCTL".to_string(),
                _ => format!("SMB2_CMD_0x{:04X}", cmd),
            };
        }
    }

    info
}

// Function extracting readable ASCII characters (folder paths) from the payload
fn extract_ascii_path(data: &[u8]) -> String {
    let path: String = data.iter()
        .take_while(|&&b| b != 0)
        .filter(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'\\')
        .map(|&b| b as char)
        .collect();
    
    if path.is_empty() { "none".to_string() } else { path }
}

// Simple heuristics to classify events into the required categories
fn classify_event(info: &ParsedSmb, raw: &[u8], src_ip: &str, event_type: &str, shared: Arc<Mutex<SharedState>>) -> (String, f64, String) {
    let now = Utc::now();

    // Record events in shared state
    {
        let mut s = shared.lock().unwrap();

        // Track auth attempts
        if event_type == "auth_attempt" {
            let entry = s.auth_attempts.entry(src_ip.to_string()).or_insert_with(Vec::new);
            entry.push(now);
            // trim older than 10s
            entry.retain(|t| (*t + chrono::Duration::seconds(10)) > now);
        }

        // Track commands seen
        let cmds = s.commands_seen.entry(src_ip.to_string()).or_insert_with(Vec::new);
        cmds.push((now, info.command.clone()));
        cmds.retain(|(t, _)| (*t + chrono::Duration::seconds(60)) > now);
    }

    // Convert raw to lower-case string for pattern checks (best-effort)
    let raw_lower = String::from_utf8_lossy(raw).to_lowercase();
    let raw_b64 = STANDARD.encode(raw);

    // Heuristic checks
    // 1) brute_force: >=10 auth_attempts within 5 seconds
    {
        let s = shared.lock().unwrap();
        if let Some(attempts) = s.auth_attempts.get(src_ip) {
            let cutoff = now - chrono::Duration::seconds(5);
            let mut recent = 0usize;
            for t in attempts.iter() {
                if t > &cutoff {
                    recent += 1;
                }
            }
            if recent >= 10 {
                let details = json!({"recent_auth_attempts": recent}).to_string();
                return ("brute_force".to_string(), 0.9, details);
            }
        }
    }

    // 2) scanning: >=20 distinct commands in last 60s
    {
        let s = shared.lock().unwrap();
        if let Some(cmds) = s.commands_seen.get(src_ip) {
            let unique: std::collections::HashSet<_> = cmds.iter().map(|(_, c)| c.clone()).collect();
            if unique.len() >= 20 {
                let details = json!({"unique_commands": unique.len()}).to_string();
                return ("scanning".to_string(), 0.8, details);
            }
        }
    }

    // 3) file_upload_malicious: payload contains executable magic or .php /.phtml filename in metadata
    if info.metadata.to_lowercase().contains(".php") || info.metadata.to_lowercase().contains(".phtml") {
        let details = json!({"reason": "suspicious_extension", "metadata": info.metadata}).to_string();
        return ("file_upload_malicious".to_string(), 0.8, details);
    }
    if raw.len() >= 2 && raw[0] == 0x4D && raw[1] == 0x5A { // MZ header
        let details = json!({"magic": "MZ", "len": raw.len()}).to_string();
        return ("file_upload_malicious".to_string(), 0.9, details);
    }

    // 4) command_injection: payload contains shell-like sequences
    let suspicious_tokens = ["; ls", "&& ", "`", "| nc", "powershell", "cmd.exe", "bash -i", "curl ", "wget "];
    for t in &suspicious_tokens {
        if raw_lower.contains(t) || info.metadata.to_lowercase().contains(t) {
            let details = json!({"token": t}).to_string();
            return ("command_injection".to_string(), 0.85, details);
        }
    }

    // 5) sql_injection: unlikely for SMB, but check payload for SQL patterns
    let sql_tokens = ["union select", " or '1'='1", "-- ", "; drop table", "mysql_fetch", "sql syntax"];
    for t in &sql_tokens {
        if raw_lower.contains(t) || info.metadata.to_lowercase().contains(t) {
            let details = json!({"token": t}).to_string();
            return ("sql_injection".to_string(), 0.7, details);
        }
    }

    // Default: unknown/benign
    let details = json!({"note": "no rule matched", "raw_b64_len": raw_b64.len()}).to_string();
    ("unknown".to_string(), 0.2, details)
}

// Pretend the folder/share connection succeeded
fn send_fake_success_response(stream: &mut TcpStream) {
    let response = [
        0x00, 0x00, 0x00, 0x07, // NetBIOS: Length 7
        0xFF, b'S', b'M', b'B', 0x75, 0x00, 0x00 // SMBv1 Header + Success Status
    ];
    let _ = stream.write_all(&response);
}

// Send random gibberish wrapped in a NetBIOS frame
fn send_chaos_response(stream: &mut TcpStream) {
    let mut rng = rand::thread_rng();
    let junk_len = rng.gen_range(24..128);
    let mut junk: Vec<u8> = (0..junk_len).map(|_| rng.gen()).collect();
    
    let len_bytes = (junk_len as u32).to_be_bytes();
    let mut response = vec![0x00]; // NetBIOS Session Message
    response.extend_from_slice(&len_bytes[1..4]);
    response.append(&mut junk);
    
    let _ = stream.write_all(&response);
}

fn init_db(path: &str) -> rusqlite::Result<()> {
    let conn = Connection::open(path)?;
    // Create table logs with required schema
    conn.execute(
        "CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            day TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            event_type TEXT,
            raw TEXT,
            parsed TEXT,
            classification TEXT,
            confidence REAL,
            details TEXT,
            headers TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS daily_summary (
            day TEXT PRIMARY KEY,
            total_events INTEGER,
            by_class TEXT,
            first_seen TEXT,
            last_seen TEXT
        )",
        [],
    )?;
    Ok(())
}

fn insert_log_record(src_ip: &str, src_port: i64, dst_port: i64, protocol: &str, event_type: &str, raw: &[u8], parsed: &ParsedSmb, classification: &str, confidence: f64, details: &str) -> rusqlite::Result<()> {
    let conn = Connection::open(DB_PATH)?;
    let now: DateTime<Utc> = SystemTime::now().into();
    let ts = now.to_rfc3339();
    let day = ts.split('T').next().unwrap_or("").to_string();

    let raw_b64 = STANDARD.encode(raw);
    let parsed_text = format!("{{\"protocol\":\"{}\",\"command\":\"{}\",\"metadata\":\"{}\"}}", parsed.protocol, parsed.command, parsed.metadata);

    conn.execute(
        "INSERT INTO logs (timestamp, day, src_ip, src_port, dst_port, protocol, event_type, raw, parsed, classification, confidence, details, headers)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![ts, day, src_ip, src_port, dst_port, protocol, event_type, raw_b64, parsed_text, classification, confidence, details, ""],
    )?;

    // Update daily_summary
    let mut stmt = conn.prepare("SELECT total_events, by_class, first_seen, last_seen FROM daily_summary WHERE day = ?1")?;
    let mut rows = stmt.query(params![day])?;
    if let Some(row) = rows.next()? {
        let total: i64 = row.get(0)?;
        let by_class: String = row.get(1)?;
        let _first_seen: String = row.get(2)?;
        let _last_seen: String = row.get(3)?;

        // merge by_class JSON
        let mut by_class_map: serde_json::Value = if by_class.is_empty() { json!({}) } else { serde_json::from_str(&by_class).unwrap_or(json!({})) };
        let count = by_class_map.get(classification).and_then(|v| v.as_i64()).unwrap_or(0) + 1;
        by_class_map[classification] = json!(count);

        conn.execute(
            "UPDATE daily_summary SET total_events = ?1, by_class = ?2, last_seen = ?3 WHERE day = ?4",
            params![total + 1, by_class_map.to_string(), ts, day],
        )?;
    } else {
        // insert new
        let mut map = serde_json::Map::new();
        map.insert(classification.to_string(), json!(1));
        conn.execute(
            "INSERT INTO daily_summary (day, total_events, by_class, first_seen, last_seen) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![day, 1, serde_json::Value::Object(map).to_string(), ts, ts],
        )?;
    }

    Ok(())
}