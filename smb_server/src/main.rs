use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use chrono::{DateTime, Utc};
use rand::Rng;
use rusqlite::{params, Connection};

// Database path inside the container
const DB_PATH: &str = "data/honeypot.db";

// Structure holding the analyzed data
struct ParsedSmb {
    protocol: String,    // e.g., SMBv1, SMBv2
    command: String,     // e.g., TREE_CONNECT, NT_CREATE
    is_negotiate: u8,    // 1 if it's a negotiation, 0 otherwise
}

fn main() -> std::io::Result<()> {
    // Wait briefly for the Docker filesystem to initialize
    std::thread::sleep(std::time::Duration::from_secs(2));

    println!("🚀 SMB Honeypot [Chaos Mode] starting...");
    
    // Database initialization
    if let Err(e) = init_db(DB_PATH) {
        eprintln!("❌ Database initialization error: {}", e);
        // Continue, we will retry during the write operation
    } else {
        println!("📂 Database connected: {}", DB_PATH);
    }

    // Listen on the SMB port
    let listener = TcpListener::bind("0.0.0.0:445")?;
    println!("👂 Listening on port 445...");

    // Global ID counter for console logs
    let global_id = Arc::new(Mutex::new(0u64));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let id_counter = Arc::clone(&global_id);
                // Handle each connection in a new thread
                std::thread::spawn(move || {
                    handle_client(stream, id_counter);
                });
            }
            Err(e) => eprintln!("TCP Connection error: {}", e),
        }
    }
    Ok(())
}

fn handle_client(mut stream: TcpStream, id_counter: Arc<Mutex<u64>>) {
    let mut buffer = [0; 4096];
    // Get the attacker's IP
    let src_addr = stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "UNKNOWN".to_string());

    // Read the first packet (usually Negotiate Protocol)
    if let Ok(size)