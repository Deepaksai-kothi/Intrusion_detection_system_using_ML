# Intrusion Detection System Using Machine Learning

This project uses a Random Forest model trained on the NSL-KDD dataset to improve intrusion detection accuracy by categorizing network traffic as either normal or malicious. It features live packet capture and real-time predictions through a Flask web application, demonstrating the adaptability of machine learning in cybersecurity. It also includes virtualization for safe attack simulation.

The system uses a Random Forest ML model to detect various types of attacks, including DoS, Probe, etc. It employs several Python modules like PyShark to capture packets and reflects the detected attacks on the frontend via a Flask web application.

## Project Setup

1. Use a virtual desktop (System 1 - Windows). For optimal performance, use VMware Workstation.
2. Set up a virtual Windows machine using VMware. Set the network connection to *bridged* mode with the host system to secure and use the IP for attack simulation.
3. Set up another virtual machine (System 2 - Kali Linux) to simulate attacks.
4. Arrange both VMs side by side on the same host for convenience.
5. Ping your virtual Windows machine (System 1) from Kali Linux (System 2) using the command:
   ```bash
   sudo ping <your_windows_ip>
   ```
   > **Note**: Disable the firewall in the Windows VM to allow the ping to succeed.
6. After the ping is successfully established, proceed to launch various attacks from Kali Linux (System 2) using the Windows IP as the target.
7. This is only a simulation, so ensure you're using virtual machines. The IDS project running on Windows (System 1) will detect the attacks.
   > **Note**: The system only detects attacks; it does not prevent or respond to them.

## Using the Project on Windows

### Step 1
Use the NSL-KDD.csv dataset from Kaggle via the link:  
https://www.kaggle.com/datasets/hassan06/nslkdd  
Alternatively, use the `NSL-KDD.csv` file from this repository.

### Step 2
Train and test the dataset using `RandomForest.py`, which generates `random_forest_model.pkl` — a trained model ready for prediction.

> **Important**: Before proceeding to the next step, start an attack using Kali Linux (System 2) on Windows (System 1). This will generate abnormal packets. Immediately after, proceed to Step 3.

### Step 3
Run `features.py`. This creates `network_features.csv`, which contains the required features for detection.  
This step captures live packets using the PyShark module in Python.

> **Note**: Update the network interface in `features.py` as needed:
```python
cap = pyshark.LiveCapture(interface="Ethernet0")
```

### Step 4
Alternatively, you can run `pcap.py` to extract features from a PCAP file. This file can be generated from Wireshark's live packet capture.

### Step 5
Run `project_server.py` (main script) to start the local server for the web application.  
Open the webpage and upload the CSV file generated in **Step 3** or **Step 4**.  
The frontend will display the attacks detected from Kali Linux, and the model will identify them accurately.

## Customizing the Web Page

You can customize the web page and its background via the `templates/` and `static/` directories.  
> `Homepage.html` is crucial for functionality — make changes carefully to avoid breaking it.
