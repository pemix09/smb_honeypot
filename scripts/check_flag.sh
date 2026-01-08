#!/usr/bin/env bash
set -euo pipefail

# Usage: scripts/check_flag.sh [HONEYPOT_IP] [SHARE]
# Example: scripts/check_flag.sh 127.0.0.1 share

DB=./data/honeypot.db
IP=${1:-127.0.0.1}
SHARE=${2:-share}
OUT=downloaded_FLAG.txt

echo "Checking honeypot //$IP/$SHARE for FLAG.txt"

GOT=0
if command -v python3 >/dev/null 2>&1; then
  echo "Attempting Python fetch using scripts/check_flag.py"
  if python3 scripts/check_flag.py "${IP}" "${SHARE}" --db "${DB}" --out "${OUT}"; then
    if [ -f "${OUT}" ]; then
      GOT=1
    fi
  else
    echo "Python attempt failed or pysmb missing — falling back to smbclient/docker method"
  fi
fi

if [ "$GOT" -eq 0 ]; then
  if command -v smbclient >/dev/null 2>&1; then
    echo "smbclient found — attempting to fetch FLAG.txt"
    TMP=$(mktemp)
    if smbclient "//$IP/$SHARE" -N -c "get FLAG.txt ${OUT}" >"${TMP}" 2>&1; then
      echo "FLAG downloaded to ${OUT} :"
      cat "${OUT}" || true
      GOT=1
    else
      echo "smbclient failed to fetch FLAG.txt (it may not exist or guest access blocked)"
      echo "--- smbclient output ---"
      sed -n '1,200p' "${TMP}" || true
      echo "------------------------"
    fi
    rm -f "${TMP}"
  else
    echo "smbclient not installed locally — attempting via Docker container"
    # On macOS use host.docker.internal to reach the host; fallback to provided IP
    DOCKER_HOST=${DOCKER_HOST:-host.docker.internal}
    TARGET=${DOCKER_HOST}
    if [ "${IP}" != "127.0.0.1" ] && [ "${IP}" != "localhost" ]; then
      TARGET=${IP}
    fi
    echo "Using target ${TARGET} inside container"
    TMP=$(mktemp)
    docker run --rm -v "$(pwd):/work" --workdir /work python:3.11-slim bash -lc "apt-get update -qq && apt-get install -y -qq smbclient && smbclient //'${TARGET}'/'${SHARE}' -N -c 'get FLAG.txt /work/${OUT}'" >"${TMP}" 2>&1 || true
    if [ -f "${OUT}" ]; then
      echo "FLAG downloaded to ${OUT} via Docker container:"
      cat "${OUT}" || true
      GOT=1
    else
      echo "Docker attempt did not retrieve FLAG.txt"
      echo "--- docker smbclient output ---"
      sed -n '1,200p' "${TMP}" || true
      echo "-------------------------------"
    fi
    rm -f "${TMP}"
  fi
fi

echo
echo "Querying honeypot DB for related log entries: ${DB}"
if [ ! -f "${DB}" ]; then
  echo "DB file not found at ${DB}. Is the compose stack running and did the proxy initialize the DB?"
  exit 0
fi

echo
echo "-- Recent logs (last 25) --"
sqlite3 "${DB}" "SELECT id,timestamp,src_ip,src_port,dst_port,protocol,event_type,classification,confidence,parsed,details FROM logs ORDER BY id DESC LIMIT 25;"

echo
echo "-- Logs mentioning FLAG or FLAG.txt (parsed/details) --"
sqlite3 "${DB}" "SELECT id,timestamp,src_ip,src_port,event_type,classification,parsed,details FROM logs WHERE parsed LIKE '%FLAG%' OR details LIKE '%FLAG%' OR parsed LIKE '%FLAG.txt%' OR details LIKE '%FLAG.txt%' ORDER BY id DESC LIMIT 50;"

echo
echo "-- Recent file-upload malicious detections --"
sqlite3 "${DB}" "SELECT id,timestamp,src_ip,src_port,event_type,classification,confidence,details FROM logs WHERE classification='file_upload_malicious' ORDER BY id DESC LIMIT 50;"

if [ "$GOT" -eq 1 ]; then
  echo
  echo "Since the script fetched the flag file locally, show DB entries from the same approximate time (last 60 seconds):"
  NOW=$(date -u +%s)
  START=$(($NOW - 60))
  sqlite3 "${DB}" "SELECT id,timestamp,src_ip,src_port,event_type,classification,details FROM logs WHERE strftime('%s', timestamp) >= $START ORDER BY id DESC;"
fi

echo
echo "Done. If you need this run from inside Docker (no local smbclient), run an ephemeral container with smbclient installed or copy this script into a container with network access to the honeypot."
