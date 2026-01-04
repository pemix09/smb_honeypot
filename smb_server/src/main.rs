use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use chrono::{DateTime, Utc};
use rand::Rng;
use rusqlite::{params, Connection};

// Ścieżka do bazy wewnątrz kontenera
const DB_PATH: &str = "data/honeypot.db";

// Struktura przechowująca przeanalizowane dane
struct ParsedSmb {
    protocol: String,    // np. SMBv1, SMBv2
    command: String,     // np. TREE_CONNECT, NT_CREATE
    is_negotiate: u8,    // 1 jeśli to negocjacja, 0 w przeciwnym razie
}

fn main() -> std::io::Result<()> {
    // Czekamy chwilę na start systemu plików w Dockerze
    std::thread::sleep(std::time::Duration::from_secs(2));

    println!("🚀 SMB Honeypot [Chaos Mode] startuje...");
    
    // Inicjalizacja bazy danych
    if let Err(e) = init_db(DB_PATH) {
        eprintln!("❌ Błąd inicjalizacji bazy danych: {}", e);
        // Kontynuujemy, spróbujemy ponownie przy zapisie
    } else {
        println!("📂 Baza danych podłączona: {}", DB_PATH);
    }

    // Nasłuchujemy na porcie SMB
    let listener = TcpListener::bind("0.0.0.0:445")?;
    println!("👂 Nasłuchiwanie na porcie 445...");

    // Globalny licznik ID dla logów konsolowych
    let global_id = Arc::new(Mutex::new(0u64));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let id_counter = Arc::clone(&global_id);
                // Każde połączenie obsługujemy w nowym wątku
                std::thread::spawn(move || {
                    handle_client(stream, id_counter);
                });
            }
            Err(e) => eprintln!("Błąd połączenia TCP: {}", e),
        }
    }
    Ok(())
}

fn handle_client(mut stream: TcpStream, id_counter: Arc<Mutex<u64>>) {
    let mut buffer = [0; 4096];
    // Pobieramy IP atakującego
    let src_addr = stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "UNKNOWN".to_string());

    // Czytamy pierwszy pakiet (zazwyczaj Negotiate Protocol)
    if let Ok(size) = stream.read(&mut buffer) {
        if size > 0 {
            // Aktualizacja licznika konsolowego
            let mut id = id_counter.lock().unwrap();
            *id += 1;
            let current_id = *id;
            drop(id);

            let raw_data = &buffer[0..size];
            
            // --- KROK 1: ANALIZA PAKIETU ---
            // Zamieniamy surowe bajty na zrozumiałe informacje
            let analysis = parse_smb_packet(raw_data);

            // --- KROK 2: ZAPIS DO BAZY ---
            if let Err(e) = log_to_sqlite(&src_addr, &analysis, raw_data) {
                eprintln!("❌ Błąd SQL: {}", e);
            }

            // Log na konsolę (dla administratora)
            println!("[#{}] {} | Proto: {} | Cmd: {}", 
                current_id, src_addr, analysis.protocol, analysis.command);

            // --- KROK 3: CHAOS RESPONSE ---
            // Wysyłamy odpowiedź, która wygląda na SMB, ale zawiera śmieci
            send_chaos_response(&mut stream);
        }
    }
}

// Inicjalizacja tabeli w SQLite
fn init_db(path: &str) -> rusqlite::Result<()> {
    let conn = Connection::open(path)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            protocol_ver TEXT NOT NULL,
            command_name TEXT NOT NULL,
            is_negotiate INTEGER NOT NULL,
            raw_payload_hex TEXT NOT NULL,
            payload_len INTEGER NOT NULL
        )",
        [],
    )?;
    Ok(())
}

// Zapis logu do bazy
fn log_to_sqlite(ip: &str, info: &ParsedSmb, raw: &[u8]) -> rusqlite::Result<()> {
    let conn = Connection::open(DB_PATH)?;
    let now: DateTime<Utc> = SystemTime::now().into();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    
    conn.execute(
        "INSERT INTO logs (timestamp, src_ip, protocol_ver, command_name, is_negotiate, raw_payload_hex, payload_len)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![timestamp, ip, info.protocol, info.command, info.is_negotiate, hex::encode(raw), raw.len() as i64],
    )?;
    Ok(())
}

// =============================================================
// INTELIGENTNY PARSER SMB (SŁOWNIK KOMEND)
// =============================================================
fn parse_smb_packet(payload: &[u8]) -> ParsedSmb {
    let mut info = ParsedSmb {
        protocol: "UNKNOWN".to_string(),
        command: "UNKNOWN".to_string(),
        is_negotiate: 0,
    };

    if payload.len() < 5 { return info; }

    // Wykrywanie nagłówka NetBIOS Session Service (4 bajty)
    // Zazwyczaj: [0x00] [Długość 3 bajty] [Nagłówek SMB]
    let mut offset = 0;
    if payload[0] == 0x00 && payload.len() > 4 {
        // Jeśli 5. bajt to 0xFF lub 0xFE, to znaczy, że mamy nagłówek NetBIOS
        if payload[4] == 0xFF || payload[4] == 0xFE {
            offset = 4;
        }
    }
    let smb_data = &payload[offset..];

    // --- PROTOKÓŁ SMBv1 (Zaczyna się od 0xFF 'S' 'M' 'B') ---
    if smb_data.len() > 4 && smb_data[0] == 0xFF && &smb_data[1..4] == b"SMB" {
        info.protocol = "SMBv1".to_string();
        
        // W SMBv1 kod komendy jest na 4. bajcie nagłówka
        if smb_data.len() > 5 {
            let cmd = smb_data[4];
            info.command = match cmd {
                0x72 => { info.is_negotiate = 1; "NEGOTIATE_PROTOCOL".to_string() },
                0x73 => "SESSION_SETUP_ANDX".to_string(),
                0x75 => "TREE_CONNECT_ANDX".to_string(),
                0x71 => "TREE_DISCONNECT".to_string(),
                0x74 => "LOGOFF_ANDX".to_string(),
                0x25 => "TRANSACTION_2".to_string(),       // Używane przy skanowaniu udziałów
                0x32 => "TRANS2_SECONDARY".to_string(),    // Często używane w exploitach
                0x2A => "NT_CREATE_ANDX".to_string(),      // Otwieranie pliku
                0x2E => "WRITE_ANDX".to_string(),          // Zapis do pliku
                0x04 => "CLOSE".to_string(),
                0x06 => "DELETE".to_string(),
                0xA0 => "NT_TRANSACT".to_string(),
                0xA2 => "NT_TRANSACT_SECONDARY".to_string(), // Kluczowe dla EternalBlue
                _ => format!("SMB1_CMD_0x{:02X}", cmd),
            };
        }
        return info;
    }

    // --- PROTOKÓŁ SMBv2 / SMBv3 (Zaczyna się od 0xFE 'S' 'M' 'B') ---
    if smb_data.len() > 4 && smb_data[0] == 0xFE && &smb_data[1..4] == b"SMB" {
        info.protocol = "SMBv2".to_string();
        
        // W SMBv2 kod komendy to 2 bajty na offsecie 12
        if smb_data.len() > 14 {
            let cmd = u16::from_le_bytes([smb_data[12], smb_data[13]]);
            info.command = match cmd {
                0x0000 => { info.is_negotiate = 1; "NEGOTIATE".to_string() },
                0x0001 => "SESSION_SETUP".to_string(),
                0x0002 => "LOGOFF".to_string(),
                0x0003 => "TREE_CONNECT".to_string(),
                0x0004 => "TREE_DISCONNECT".to_string(),
                0x0005 => "CREATE".to_string(),
                0x0006 => "CLOSE".to_string(),
                0x0007 => "FLUSH".to_string(),
                0x0008 => "READ".to_string(),
                0x0009 => "WRITE".to_string(),
                0x000B => "IOCTL".to_string(),        // Info o systemie
                0x000D => "ECHO".to_string(),         // "Ping" SMB
                0x0010 => "QUERY_DIRECTORY".to_string(),
                0x0011 => "CHANGE_NOTIFY".to_string(),
                0x0012 => "QUERY_INFO".to_string(),
                _ => format!("SMB2_CMD_0x{:04X}", cmd),
            };
        }
        return info;
    }

    info
}

// =============================================================
// ODPOWIEDŹ CHAOSU
// =============================================================
fn send_chaos_response(stream: &mut TcpStream) {
    let mut rng = rand::thread_rng();
    
    // 1. Generujemy losowy rozmiar payloadu (20-100 bajtów)
    let junk_len = rng.gen_range(20..100);
    let mut junk_payload = vec![0u8; junk_len];
    rng.fill(&mut junk_payload[..]);

    // 2. Tworzymy poprawny nagłówek NetBIOS (Session Message)
    // Format: [0x00] [Długość: 3 bajty Big Endian]
    // Dzięki temu narzędzia takie jak Nmap myślą: "O, to jest usługa NetBIOS/SMB!",
    // odbierają pakiet, a potem próbują sparsować śmieci w środku i głupieją.
    let len_bytes = (junk_len as u32).to_be_bytes();
    
    let mut response = Vec::new();
    response.push(0x00); 
    response.extend_from_slice(&len_bytes[1..4]); // Ostatnie 3 bajty
    response.extend_from_slice(&junk_payload);    // Losowe dane

    // 3. Wysyłamy i nie zamykamy połączenia natychmiast
    // (niech klient się pomęczy z analizą)
    let _ = stream.write_all(&response);
}