from scapy.all import sniff, get_if_list, IP, TCP, UDP
import sys
import time
from collections import defaultdict
import os
import csv
from datetime import datetime

# --- Configurations ---
SERVER_IP = "192.168.1.27"  # Change to your server IP
WINDOW_SECONDS = 5
CSV_FILE = "trafego_final.csv"

# --- Data structure ---
# Format: { 'client_ip': { 'PROTOCOL': {'IN': X, 'OUT': Y} } }
window_data = defaultdict(lambda: defaultdict(lambda: {'IN': 0, 'OUT': 0}))
window_start = time.time()

def initialize_csv():
    # Create CSV file with header if it doesn't exist
    try:
        with open(CSV_FILE, "x", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "client_ip", "protocol", "traffic_in_bytes", "traffic_out_bytes"])
    except FileExistsError:
        pass

def process_packet(packet):
    global window_start
    
    # Check if window time elapsed
    if time.time() - window_start > WINDOW_SECONDS:
        save_and_reset_window()

    # Filter packets related to SERVER_IP
    if not packet.haslayer(IP) or (packet[IP].src != SERVER_IP and packet[IP].dst != SERVER_IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    pkt_len = len(packet)

    if packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"
    else:
        protocol = "Other"

    if src_ip == SERVER_IP:
        client_ip = dst_ip
        window_data[client_ip][protocol]['OUT'] += pkt_len
    else:
        client_ip = src_ip
        window_data[client_ip][protocol]['IN'] += pkt_len

def save_and_reset_window():
    global window_data, window_start
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for client, protocols in window_data.items():
            for proto, data in protocols.items():
                if data['IN'] > 0 or data['OUT'] > 0:
                    writer.writerow([timestamp, client, proto, data['IN'], data['OUT']])

    # Clear console and print summary
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"--- Data window saved at {timestamp} to '{CSV_FILE}' ---")
    if not window_data:
        print("No relevant traffic captured.")
    else:
        for client, protocols in sorted(window_data.items()):
            for proto, data in protocols.items():
                print(f"Client: {client} [{proto}] | IN: {data['IN']} B | OUT: {data['OUT']} B")

    window_data.clear()
    window_start = time.time()

def choose_interface():
    print("Detecting network interfaces...")
    try:
        from scapy.arch.windows import get_windows_if_list
        interfaces = get_windows_if_list()
        for i, iface in enumerate(interfaces):
            print(f"  {i}: {iface['name']} ({iface.get('description', 'N/A')})")
        choice = int(input("Enter the NUMBER of the interface to monitor: "))
        return interfaces[choice]['name']
    except Exception:
        interfaces = get_if_list()
        for i, iface_name in enumerate(interfaces):
            print(f"  {i}: {iface_name}")
        try:
            choice = int(input("Enter the NUMBER of the interface: "))
            return interfaces[choice]
        except (ValueError, IndexError):
            print("[ERROR] Invalid choice. Exiting.")
            sys.exit(1)

if __name__ == "__main__":
    initialize_csv()
    selected_interface = choose_interface()
    
    print(f"\nStarting capture on interface: '{selected_interface}'...")
    print(f"Saving data every {WINDOW_SECONDS} seconds to '{CSV_FILE}'.")
    print("Press Ctrl+C to stop.")
    time.sleep(2)

    try:
        sniff(iface=selected_interface, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n\n--- Capture stopped. Saving last data window... ---")
        save_and_reset_window()