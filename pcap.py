import pyshark
import pandas as pd
import numpy as np
from collections import defaultdict

# Path to the pcap file
PCAP_FILE = "featurs.pcapng"

# Read packets from the PCAP file
cap = pyshark.FileCapture(PCAP_FILE)

# Feature dictionary to store extracted features
traffic_data = defaultdict(lambda: {
    "logged_in": 0,
    "root_shell": 0,
    "su_attempted": 0,
    "duration": 0,
    "src_bytes": 0,
    "dst_bytes": 0,
    "hot": 0,
    "num_failed_logins": 0,
    "num_compromised": 0,
    "num_file_creations": 0,
    "num_shells": 0,
    "num_access_files": 0,
    "count": 0,
    "srv_count": 0,
    "serror_rate": 0,
    "srv_serror_rate": 0,
    "rerror_rate": 0,
    "srv_rerror_rate": 0,
    "dst_host_count": 0,
    "dst_host_srv_count": 0,
    "dst_host_same_srv_rate": 0,
    "dst_host_diff_srv_rate": 0,
    "dst_host_serror_rate": 0,
    "dst_host_srv_serror_rate": 0,
})

# Packet processing loop
for packet in cap:
    try:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else "N/A"
        packet_length = int(packet.length) if hasattr(packet, 'length') else 1500

        # TCP Flags (if TCP exists)
        flags = packet.tcp.flags if hasattr(packet, 'tcp') else None

        # Feature calculations
        traffic_data[src_ip]["src_bytes"] += packet_length
        traffic_data[dst_ip]["dst_bytes"] += packet_length

        # Error and attack-related features
        if flags:
            traffic_data[src_ip]["serror_rate"] += 1
            traffic_data[src_ip]["rerror_rate"] += 1

        # Count number of packets to destination
        traffic_data[dst_ip]["dst_host_count"] += 1
        traffic_data[dst_ip]["dst_host_srv_count"] += 1  # Assuming same service

    except Exception as e:
        print(f"Error processing packet: {e}")

# Convert to Pandas DataFrame
df = pd.DataFrame.from_dict(traffic_data, orient="index")

# Normalize error rates to avoid division by zero
df["serror_rate"] = df["serror_rate"] / df["dst_host_count"].replace(0, 1)
df["rerror_rate"] = df["rerror_rate"] / df["dst_host_count"].replace(0, 1)

# Fill NaN values (if division by zero occurs)
df.fillna(0, inplace=True)

# Only keep features used for prediction
selected_features = [
    'duration', 'src_bytes', 'dst_bytes', 'hot', 'num_failed_logins', 'logged_in', 
    'num_compromised', 'root_shell', 'su_attempted', 'num_file_creations', 
    'num_shells', 'num_access_files', 'count', 'srv_count', 'serror_rate', 
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'dst_host_count', 
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 
    'dst_host_serror_rate', 'dst_host_srv_serror_rate'
]

# Ensure all features exist in the DataFrame
df = df.reindex(columns=selected_features, fill_value=0)

# Print and save extracted features
print(df.head())
df.to_csv("network_features.csv", index=True)
