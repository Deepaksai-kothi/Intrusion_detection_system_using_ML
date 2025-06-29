import sys
sys.stdout.reconfigure(encoding='utf-8')
import pyshark
import pandas as pd
import time
from collections import defaultdict
import asyncio

# Initialize feature counters
traffic_data = defaultdict(lambda: {
    "logged_in": 0,
    "root_shell": 0,
    "su_attempted": 0,
    "outcome": 0,
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
    "level": 0,
})

# Live capture from network interface (Update if needed)
cap = pyshark.LiveCapture(interface="Ethernet0")

def packet_callback(packet):
    try:
        if 'ip' not in packet:
            return

        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        protocol = getattr(packet, 'transport_layer', 'N/A')
        packet_length = int(getattr(packet, 'length', 1500))
        flags = packet.tcp.flags if hasattr(packet, 'tcp') else None

        traffic_data[src_ip]["src_bytes"] += packet_length
        traffic_data[dst_ip]["dst_bytes"] += packet_length

        if flags and '0x0002' in flags:
            traffic_data[src_ip]["serror_rate"] += 1
        if flags and '0x0004' in flags:
            traffic_data[src_ip]["rerror_rate"] += 1

        traffic_data[dst_ip]["dst_host_count"] += 1
        traffic_data[dst_ip]["dst_host_srv_count"] += 1

    except Exception as e:
        print(f"Error processing packet: {e}")

# Start capturing packets for 10 seconds
try:
    cap.apply_on_packets(packet_callback, timeout=10)
except asyncio.exceptions.CancelledError:
    print("Capture timeout reached.")
except Exception as e:
    print(f"Unexpected error: {e}")

# Convert to DataFrame
df = pd.DataFrame.from_dict(traffic_data, orient="index")

# Normalize error rates
df["serror_rate"] = df["serror_rate"] / df["dst_host_count"].replace(0, 1)
df["rerror_rate"] = df["rerror_rate"] / df["dst_host_count"].replace(0, 1)

df.fillna(0, inplace=True)

# Check required features
required_features = [
    "logged_in", "root_shell", "su_attempted", "outcome", "duration", "src_bytes", "dst_bytes", "hot",
    "num_failed_logins", "num_compromised", "num_file_creations", "num_shells", "num_access_files",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "level"
]

missing = [f for f in required_features if f not in df.columns]
zeroed = [f for f in required_features if f in df.columns and df[f].sum() == 0]

print("\nFeature Assignment Check:")
print("All required features are present." if not missing else f"Missing Features: {missing}")
print("No feature has only zero values." if not zeroed else f"Features with only zero values: {zeroed}")

print("\nFeature Stats:")
print(df.describe())
df["zero_feature_count"] = (df[required_features] == 0).sum(axis=1)
print("\nRows with too many zero features:\n", df[df["zero_feature_count"] > 20])
# Save as CSV
df.to_csv("network_features.csv", index=True)
print("\nSaved network_features.csv successfully.")