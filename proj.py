import pyshark
import pandas as pd
import os
import smtplib
from sklearn.ensemble import RandomForestClassifier
import joblib
from email.mime.text import MIMEText
import sqlite3

# Load pre-trained ML model
model = joblib.load("ml_idps_model.pkl")

# Email alert configuration
EMAIL_ADDRESS = "your_email@example.com"
EMAIL_PASSWORD = "your_password"
ALERT_RECIPIENT = "admin@example.com"

# Database setup
DB_NAME = "idps_logs.db"

def setup_database():
    """Sets up the SQLite database for logging."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            source_ip TEXT,
            timestamp TEXT,
            details TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_alert(source_ip, details):
    """Logs an alert in the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO alerts (source_ip, timestamp, details) VALUES (?, datetime('now'), ?)",
                   (source_ip, details))
    conn.commit()
    conn.close()

def send_alert(packet_info):
    """Sends an email alert with packet details."""
    try:
        msg = MIMEText(f"Malicious activity detected:\n\n{packet_info}")
        msg['Subject'] = "IDPS Alert: Threat Detected"
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = ALERT_RECIPIENT

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, ALERT_RECIPIENT, msg.as_string())
            print("Alert email sent successfully!")
    except Exception as e:
        print(f"Failed to send alert email: {e}")

def block_ip(ip_address):
    """Blocks the IP address using iptables."""
    try:
        os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
        print(f"Blocked IP address: {ip_address}")
    except Exception as e:
        print(f"Failed to block IP: {e}")

def extract_features(packet):
    """Extracts relevant features from a packet for ML classification."""
    features = {}
    try:
        features['length'] = int(packet.length)
        features['protocol'] = 1 if packet.highest_layer == 'TCP' else 0
        features['source_port'] = int(packet.tcp.srcport) if 'TCP' in packet else 0
        features['destination_port'] = int(packet.tcp.dstport) if 'TCP' in packet else 0
        features['flags'] = int(packet.tcp.flags) if 'TCP' in packet else 0
    except AttributeError:
        pass
    return features

def monitor_traffic():
    """Monitors network traffic for malicious activity."""
    capture = pyshark.LiveCapture(interface='eth0')  # Replace with your network interface
    for packet in capture.sniff_continuously(packet_count=10):  # Adjust packet count
        try:
            # Extract features
            features = extract_features(packet)
            features_df = pd.DataFrame([features])

            # Predict malicious activity
            prediction = model.predict(features_df)
            if prediction[0] == 1:  # Assuming 1 indicates malicious
                source_ip = packet.ip.src if hasattr(packet, 'ip') else 'Unknown'
                print(f"Alert: Malicious packet detected from {source_ip}")

                # Log, alert, and block IP
                log_alert(source_ip, f"Malicious packet detected: {packet}")
                send_alert(f"Source IP: {source_ip}\nPacket Details: {packet}")
                block_ip(source_ip)
        except Exception as e:
            print(f"Error processing packet: {e}")

if __name__ == "__main__":
    print("Starting Intrusion Detection and Prevention System...")
    setup_database()
    monitor_traffic()
