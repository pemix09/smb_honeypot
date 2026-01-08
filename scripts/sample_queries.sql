-- name: recent_logs
SELECT id,timestamp,day,src_ip,src_port,dst_port,protocol,event_type,classification,confidence,details FROM logs ORDER BY id DESC LIMIT 100;

-- name: brute_force_events
SELECT id,timestamp,src_ip,src_port,event_type,classification,confidence,details FROM logs WHERE classification='brute_force' ORDER BY timestamp DESC LIMIT 200;

-- name: top_attackers
SELECT src_ip, COUNT(*) as attempts FROM logs GROUP BY src_ip ORDER BY attempts DESC LIMIT 20;

-- name: scanning_events
SELECT id,timestamp,src_ip,event_type,classification,details FROM logs WHERE classification='scanning' ORDER BY timestamp DESC LIMIT 200;

-- name: suspicious_uploads
SELECT id,timestamp,src_ip,event_type,classification,details,parsed FROM logs WHERE classification='file_upload_malicious' OR details LIKE '%suspicious_extension%' ORDER BY timestamp DESC LIMIT 200;

-- name: command_injections
SELECT id,timestamp,src_ip,event_type,classification,details,parsed FROM logs WHERE classification='command_injection' ORDER BY timestamp DESC LIMIT 200;

-- name: daily_summary
SELECT day, total_events, by_class, first_seen, last_seen FROM daily_summary ORDER BY day DESC LIMIT 30;

-- legacy queries for older DB schema (no `day`, no ports, no classification)
-- name: recent_logs_legacy
SELECT id,timestamp,src_ip,protocol_ver AS protocol,command_name AS event_type,raw_payload_hex AS raw FROM logs ORDER BY id DESC LIMIT 100;

-- name: top_attackers_legacy
SELECT src_ip, COUNT(*) as attempts FROM logs GROUP BY src_ip ORDER BY attempts DESC LIMIT 20;
