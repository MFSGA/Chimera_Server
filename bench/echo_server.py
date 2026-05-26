#!/usr/bin/env python3
import socket
import argparse
import sys
import os
import json
import time
import signal

def handle_connection(conn, addr, sync_byte, timeout, log_json):
    """Handle a single TCP connection with sync-byte protocol."""
    conn.settimeout(timeout)
    start_time = time.time()
    bytes_received = 0
    bytes_sent = 0

    try:
        # Read all data from client (until EOF)
        data = b''
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        bytes_received = len(data)

        # Send sync byte
        conn.sendall(sync_byte)
        bytes_sent += len(sync_byte)

        # Echo back received data
        conn.sendall(data)
        bytes_sent += len(data)

    except socket.timeout:
        pass  # Idle timeout, just close connection
    except ConnectionResetError:
        pass  # Client disconnected abruptly
    finally:
        conn.close()

    duration = time.time() - start_time

    if log_json:
        log_entry = {
            "bytes_received": bytes_received,
            "bytes_sent": bytes_sent,
            "duration_sec": round(duration, 6)
        }
        print(json.dumps(log_entry), flush=True)

def main():
    parser = argparse.ArgumentParser(description='Sync-byte TCP echo server')
    parser.add_argument('--port', type=int, default=20000, help='Port to listen on (default: 20000)')
    parser.add_argument('--bind', type=str, default='127.0.0.1', help='Address to bind to (default: 127.0.0.1)')
    parser.add_argument('--sync-byte', type=str, default='AC', help='Sync byte as hex (default: AC)')
    parser.add_argument('--log-json', action='store_true', help='Output JSON logs per connection to stdout')
    parser.add_argument('--timeout', type=int, default=30, help='Connection idle timeout in seconds (default: 30)')
    args = parser.parse_args()

    # Convert sync-byte from hex string to bytes
    try:
        sync_byte = bytes.fromhex(args.sync_byte)
        if len(sync_byte) != 1:
            raise ValueError("Sync byte must be exactly one byte (two hex digits)")
    except ValueError as e:
        sys.stderr.write(f"Error: Invalid sync-byte '{args.sync_byte}': {e}\n")
        sys.exit(1)

    # Set up signal handling for graceful shutdown
    state = {'shutdown': False, 'listen_sock': None}

    def signal_handler(sig, frame):
        state['shutdown'] = True
        if state['listen_sock']:
            state['listen_sock'].close()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Create listening socket
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_sock.bind((args.bind, args.port))
        listen_sock.listen(1)
    except OSError as e:
        sys.stderr.write(f"Error: Failed to bind to {args.bind}:{args.port}: {e}\n")
        sys.exit(1)

    state['listen_sock'] = listen_sock
    listen_sock.settimeout(1.0)  # Timeout for accept to check shutdown flag

    # Print listening message to stderr
    sys.stderr.write(f"LISTENING on {args.bind}:{args.port}\n")
    sys.stderr.flush()

    # Main accept loop
    while not state['shutdown']:
        try:
            conn, addr = listen_sock.accept()
        except socket.timeout:
            continue  # Check shutdown flag again
        except OSError:
            break  # Socket closed due to signal

        # Handle connection sequentially (one at a time)
        handle_connection(conn, addr, sync_byte, args.timeout, args.log_json)

    # Clean up
    listen_sock.close()
    sys.stderr.write("Shutdown complete\n")
    sys.stderr.flush()

if __name__ == '__main__':
    main()