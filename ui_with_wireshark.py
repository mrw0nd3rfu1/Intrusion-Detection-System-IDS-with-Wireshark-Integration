def get_status(self):
        """Get current capture status"""
        return getattr(self, 'capture_status', 'Ready')# ui_with_wireshark.py
import streamlit as st
import torch
import pandas as pd
import numpy as np
from utils import preprocess_data, IntrusionDataset
from models import CNNIDS, LSTMIDS, TransformerIDS
from sklearn.preprocessing import LabelEncoder
from torch.utils.data import DataLoader
import json
import subprocess
import os
import time
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import tempfile
import threading
from collections import defaultdict

# Loading the Model into the UI
def load_model(model_type, model_path, device):
    checkpoint = torch.load(model_path, map_location=device)
    
    # Read the saved model parameters
    num_classes = checkpoint["num_classes"]
    input_dim = checkpoint["input_dim"]

    # Create model with correct architecture
    if model_type == "CNN":
        model = CNNIDS(input_dim, num_classes)
    elif model_type == "LSTM":
        model = LSTMIDS(input_dim, 64, num_classes)
    elif model_type == "Transformer":
        model = TransformerIDS(input_dim, num_classes)
    
    # Load the trained weights
    model.load_state_dict(checkpoint["model_state_dict"])
    model.to(device)
    model.eval()
    
    return model, num_classes, input_dim

# Prediction function
def predict_data(df, model, device, label_encoder):
    df_proc = preprocess_data(df)

    # If no label column, use all columns as features
    if "label" not in df_proc.columns:
        X = df_proc.values.astype(np.float32)
    else:
        X = df_proc.drop("label", axis=1).values.astype(np.float32)

    dataset = torch.utils.data.TensorDataset(torch.tensor(X))
    loader = DataLoader(dataset, batch_size=64, shuffle=False)

    preds = []
    model.eval()
    with torch.no_grad():
        for batch in loader:
            data = batch[0].to(device)
            outputs = model(data)
            _, predicted = torch.max(outputs, 1)
            preds.extend(predicted.cpu().numpy())

    if label_encoder is not None:
        preds = label_encoder.inverse_transform(preds)

    return preds

# Wireshark Integration Functions
class PacketCapture:
    def __init__(self):
        self.packets = []
        self.capturing = False
        self.capture_thread = None
        
    def packet_handler(self, packet):
        """Handle captured packets and extract features"""
        if IP in packet:
            features = self.extract_features(packet)
            if features:
                self.packets.append(features)
    
    def extract_features(self, packet):
        """Extract network flow features from packet - Enhanced to match KDD Cup 99 features"""
        try:
            features = {}
            
            # Basic packet info
            features['duration'] = 0  # Single packet, so duration is 0
            features['src_bytes'] = len(packet)
            features['dst_bytes'] = len(packet)  # For single packet, using same value
            
            # Protocol information
            if TCP in packet:
                features['protocol_type'] = 'tcp'
                features['service'] = self.get_service_name_from_port(packet[TCP].dport)
                features['flag'] = self.get_tcp_flag_name(packet[TCP])
                
                # TCP specific features
                features['urgent'] = 1 if packet[TCP].flags.U else 0
                features['wrong_fragment'] = 0  # Cannot determine from single packet
                
            elif UDP in packet:
                features['protocol_type'] = 'udp'
                features['service'] = self.get_service_name_from_port(packet[UDP].dport)
                features['flag'] = 'SF'  # UDP doesn't have flags, use standard
                features['urgent'] = 0
                features['wrong_fragment'] = 0
                
            elif ICMP in packet:
                features['protocol_type'] = 'icmp'
                features['service'] = 'ecr_i'  # ICMP service
                features['flag'] = 'SF'
                features['urgent'] = 0
                features['wrong_fragment'] = 0
            else:
                features['protocol_type'] = 'other'
                features['service'] = 'other'
                features['flag'] = 'OTH'
                features['urgent'] = 0
                features['wrong_fragment'] = 0
            
            # Check for land attack (same src and dst)
            if IP in packet:
                features['land'] = 1 if packet[IP].src == packet[IP].dst else 0
            else:
                features['land'] = 0
            
            # Content features (simplified - would need payload analysis)
            features['hot'] = 0
            features['num_failed_logins'] = 0
            features['logged_in'] = 0
            features['num_compromised'] = 0
            features['root_shell'] = 0
            features['su_attempted'] = 0
            features['num_root'] = 0
            features['num_file_creations'] = 0
            features['num_shells'] = 0
            features['num_access_files'] = 0
            features['num_outbound_cmds'] = 0
            features['is_host_login'] = 0
            features['is_guest_login'] = 0
            
            # Traffic features (simplified for single packet)
            features['count'] = 1
            features['srv_count'] = 1
            features['serror_rate'] = 0.0
            features['srv_serror_rate'] = 0.0
            features['rerror_rate'] = 0.0
            features['srv_rerror_rate'] = 0.0
            features['same_srv_rate'] = 1.0
            features['diff_srv_rate'] = 0.0
            features['srv_diff_host_rate'] = 0.0
            
            # Host-based features (simplified)
            features['dst_host_count'] = 1
            features['dst_host_srv_count'] = 1
            features['dst_host_same_srv_rate'] = 1.0
            features['dst_host_diff_srv_rate'] = 0.0
            features['dst_host_same_src_port_rate'] = 1.0
            features['dst_host_srv_diff_host_rate'] = 0.0
            features['dst_host_serror_rate'] = 0.0
            features['dst_host_srv_serror_rate'] = 0.0
            features['dst_host_rerror_rate'] = 0.0
            features['dst_host_srv_rerror_rate'] = 0.0
            
            return features
            
        except Exception as e:
            st.error(f"Error extracting features: {e}")
            return None
    
    def get_service_name_from_port(self, port):
        """Map common ports to service names (KDD Cup 99 format)"""
        service_map = {
            21: 'ftp_data', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'domain_u', 80: 'http', 110: 'pop_3', 143: 'imap4',
            443: 'https', 993: 'imaps', 995: 'pop3s', 20: 'ftp',
            513: 'login', 514: 'shell', 79: 'finger', 111: 'sunrpc',
            119: 'nntp', 139: 'netbios_ssn', 445: 'microsoft_ds'
        }
        return service_map.get(port, 'private')
    
    def get_tcp_flag_name(self, tcp_layer):
        """Convert TCP flags to KDD Cup 99 flag names"""
        if tcp_layer.flags.S and not tcp_layer.flags.A:
            return 'S0'  # SYN
        elif tcp_layer.flags.S and tcp_layer.flags.A:
            return 'S1'  # SYN-ACK
        elif tcp_layer.flags.F:
            return 'SF'  # Normal connection
        elif tcp_layer.flags.R:
            return 'REJ' # Reset
        elif tcp_layer.flags.A:
            return 'SF'  # Established connection
        else:
            return 'OTH' # Other
    
    def start_capture(self, interface, duration):
        """Start packet capture with Windows compatibility"""
        self.packets = []
        self.capturing = True
        self.capture_status = "Starting..."
        
        def capture_packets():
            try:
                self.capture_status = f"Capturing on {interface}..."
                
                # Try Layer 2 capture first
                try:
                    if interface == "any":
                        sniff(prn=self.packet_handler, timeout=duration, 
                             stop_filter=lambda x: not self.capturing, store=0)
                    else:
                        sniff(iface=interface, prn=self.packet_handler, 
                             timeout=duration, stop_filter=lambda x: not self.capturing, store=0)
                except Exception as layer2_error:
                    # Fallback to Layer 3 for Windows without WinPcap
                    self.capture_status = "Trying Layer 3 capture (Windows fallback)..."
                    from scapy.config import conf
                    from scapy.arch.windows import L3WinSocket
                    
                    # Use Layer 3 socket for Windows
                    conf.L3socket = L3WinSocket
                    sniff(prn=self.packet_handler, timeout=duration,
                         stop_filter=lambda x: not self.capturing, store=0)
                    
                self.capture_status = "Capture completed"
            except PermissionError:
                self.capture_status = "Permission denied. Try running as administrator."
            except ImportError:
                self.capture_status = "Please install Npcap from https://nmap.org/npcap/ or try the simulation mode below."
            except Exception as e:
                self.capture_status = f"Capture failed: {str(e)}. Try simulation mode below."
            finally:
                self.capturing = False
        
        self.capture_thread = threading.Thread(target=capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
    def simulate_traffic(self, packet_count=10):
        """Simulate network traffic for testing purposes"""
        import random
        
        self.packets = []
        protocols = ['tcp', 'udp', 'icmp']
        services = ['http', 'https', 'smtp', 'ftp', 'ssh', 'telnet', 'private']
        flags = ['SF', 'S0', 'REJ', 'S1']
        
        for i in range(packet_count):
            # Generate realistic packet data
            packet = {
                'duration': random.uniform(0, 10),
                'protocol_type': random.choice(protocols),
                'service': random.choice(services),
                'flag': random.choice(flags),
                'src_bytes': random.randint(0, 5000),
                'dst_bytes': random.randint(0, 5000),
                'land': random.choice([0, 0, 0, 1]),  # Mostly normal
                'wrong_fragment': 0,
                'urgent': 0,
                'hot': random.randint(0, 5),
                'num_failed_logins': random.choice([0, 0, 0, 1, 2]),
                'logged_in': random.choice([0, 1]),
                'num_compromised': 0,
                'root_shell': 0,
                'su_attempted': 0,
                'num_root': 0,
                'num_file_creations': random.randint(0, 2),
                'num_shells': 0,
                'num_access_files': random.randint(0, 2),
                'num_outbound_cmds': 0,
                'is_host_login': 0,
                'is_guest_login': random.choice([0, 0, 0, 1]),
                'count': random.randint(1, 20),
                'srv_count': random.randint(1, 10),
                'serror_rate': random.uniform(0, 0.1),
                'srv_serror_rate': random.uniform(0, 0.1),
                'rerror_rate': random.uniform(0, 0.1),
                'srv_rerror_rate': random.uniform(0, 0.1),
                'same_srv_rate': random.uniform(0.5, 1.0),
                'diff_srv_rate': random.uniform(0, 0.5),
                'srv_diff_host_rate': random.uniform(0, 0.3),
                'dst_host_count': random.randint(1, 255),
                'dst_host_srv_count': random.randint(1, 100),
                'dst_host_same_srv_rate': random.uniform(0.5, 1.0),
                'dst_host_diff_srv_rate': random.uniform(0, 0.5),
                'dst_host_same_src_port_rate': random.uniform(0.3, 1.0),
                'dst_host_srv_diff_host_rate': random.uniform(0, 0.3),
                'dst_host_serror_rate': random.uniform(0, 0.1),
                'dst_host_srv_serror_rate': random.uniform(0, 0.1),
                'dst_host_rerror_rate': random.uniform(0, 0.1),
                'dst_host_srv_rerror_rate': random.uniform(0, 0.1)
            }
            
            # Add some attack patterns occasionally
            if random.random() < 0.2:  # 20% chance of suspicious activity
                if random.choice([True, False]):
                    # Port scan pattern
                    packet.update({
                        'flag': 'S0',
                        'src_bytes': 0,
                        'dst_bytes': 0,
                        'serror_rate': 1.0,
                        'count': random.randint(50, 200)
                    })
                else:
                    # Buffer overflow pattern
                    packet.update({
                        'service': 'private',
                        'hot': random.randint(10, 30),
                        'num_compromised': random.randint(1, 5)
                    })
            
            self.packets.append(packet)
        
        self.capture_status = f"Generated {packet_count} simulated packets"
    
    def get_status(self):
        """Get current capture status"""
        return getattr(self, 'capture_status', 'Ready')
    
    def stop_capture(self):
        """Stop packet capture"""
        self.capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
    
    def get_packets_as_dataframe(self):
        """Convert captured packets to DataFrame"""
        if not self.packets:
            return None
        return pd.DataFrame(self.packets)

# Function to get available network interfaces
def get_network_interfaces():
    """Get list of available network interfaces"""
    try:
        interfaces = get_if_list()
        # Add 'any' option for capturing on all interfaces
        interfaces.insert(0, "any")
        return interfaces
    except:
        return ['any', 'eth0', 'wlan0', 'lo', 'WiFi', 'Ethernet']  # Default fallback with common Windows/Linux names

# Function to read PCAP files
def read_pcap_file(pcap_file):
    """Read and process PCAP file"""
    try:
        packets = rdpcap(pcap_file)
        capture = PacketCapture()
        
        processed_packets = []
        for packet in packets:
            features = capture.extract_features(packet)
            if features:
                processed_packets.append(features)
        
        if processed_packets:
            return pd.DataFrame(processed_packets)
        else:
            return None
    except Exception as e:
        st.error(f"Error reading PCAP file: {e}")
        return None

# Main Streamlit UI
st.set_page_config(page_title="IDS with Wireshark", layout="wide")
st.title("🔍 Intrusion Detection System (IDS) - With Wireshark Integration")

# Initialize session state
if 'capture' not in st.session_state:
    st.session_state.capture = PacketCapture()

st.sidebar.header("⚙️ Settings")
model_type = st.sidebar.selectbox("Choose Model Type", ["CNN", "LSTM", "Transformer"])
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
st.sidebar.info(f"Using device: {device}")

# Label encoder for decoding predictions
label_encoder = LabelEncoder()
# Fit it with known classes
label_encoder.fit([
    "normal", "neptune", "smurf", "guess_passwd", "buffer_overflow",
    "back", "satan", "warezclient", "ipsweep", "portsweep",
    "teardrop", "pod", "nmap", "loadmodule", "ftp_write",
    "multihop", "rootkit", "phf", "spy", "imap",
    "warezmaster", "land"
])

# Create tabs for different input methods
tab1, tab2, tab3, tab4 = st.tabs(["📁 Upload CSV", "📊 Single Record", "🔴 Live Capture", "📄 PCAP File"])

with tab1:
    st.header("Upload CSV Dataset")
    uploaded_file = st.file_uploader("Upload CSV file", type=["csv"])
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        st.write("### Preview of Uploaded Data")
        st.dataframe(df.head())

        if st.button("🔍 Predict for Dataset", key="csv_predict"):
            with st.spinner("Loading model and making predictions..."):
                try:
                    model, num_classes, input_dim = load_model(model_type, f"saved_model_{model_type}.pt", device)
                    results = predict_data(df, model, device, label_encoder)
                    
                    # Display results
                    results_df = pd.DataFrame({'Prediction': results})
                    st.write("### 📊 Prediction Results")
                    st.dataframe(results_df)
                    
                    # Show prediction distribution
                    pred_counts = pd.Series(results).value_counts()
                    st.write("### 📈 Prediction Distribution")
                    st.bar_chart(pred_counts)
                    
                except Exception as e:
                    st.error(f"Prediction failed: {e}")

with tab2:
    st.header("Enter Single Network Record")
    st.info("Enter values for one network connection record:")
    
    col1, col2 = st.columns(2)
    
    single_row = {}
    
    # Define features with their types and options
    feature_definitions = {
        # Categorical features
        'protocol_type': {'type': 'categorical', 'options': ['tcp', 'udp', 'icmp']},
        'service': {'type': 'categorical', 'options': ['http', 'smtp', 'finger', 'domain_u', 'auth', 'telnet', 'ftp', 'eco_i', 'ntp_u', 'ecr_i', 'other', 'private', 'pop_3', 'ftp_data', 'rje', 'time', 'mtp', 'link', 'remote_job', 'gopher', 'ssh', 'name', 'whois', 'domain', 'login', 'imap4', 'daytime', 'ctf', 'nntp', 'shell', 'IRC', 'nnsp', 'http_443', 'exec', 'printer', 'efs', 'courier', 'uucp', 'klogin', 'kshell', 'echo', 'discard', 'systat', 'supdup', 'iso_tsap', 'hostnames', 'csnet_ns', 'pop_2', 'sunrpc', 'uucp_path', 'netbios_ns', 'netbios_ssn', 'netbios_dgm', 'sql_net', 'vmnet', 'bgp', 'Z39_50', 'ldap', 'netstat', 'urh_i', 'X11', 'urp_i', 'pm_dump', 'tftp_u', 'tim_i', 'red_i']},
        'flag': {'type': 'categorical', 'options': ['SF', 'S0', 'REJ', 'RSTR', 'RSTO', 'SH', 'S1', 'S2', 'RSTOS0', 'S3', 'OTH']},
        
        # Numeric features
        'duration': {'type': 'numeric', 'min': 0.0, 'max': 10000.0, 'default': 0.0},
        'src_bytes': {'type': 'numeric', 'min': 0, 'max': 1000000, 'default': 0},
        'dst_bytes': {'type': 'numeric', 'min': 0, 'max': 1000000, 'default': 0},
        
        # Binary features
        'land': {'type': 'binary'},
        'wrong_fragment': {'type': 'binary'},
        'urgent': {'type': 'binary'},
        'hot': {'type': 'numeric', 'min': 0, 'max': 100, 'default': 0},
        'num_failed_logins': {'type': 'numeric', 'min': 0, 'max': 10, 'default': 0},
        'logged_in': {'type': 'binary'},
        'num_compromised': {'type': 'numeric', 'min': 0, 'max': 100, 'default': 0},
        'root_shell': {'type': 'binary'},
        'su_attempted': {'type': 'binary'},
        'num_root': {'type': 'numeric', 'min': 0, 'max': 100, 'default': 0},
        'num_file_creations': {'type': 'numeric', 'min': 0, 'max': 100, 'default': 0},
        'num_shells': {'type': 'numeric', 'min': 0, 'max': 10, 'default': 0},
        'num_access_files': {'type': 'numeric', 'min': 0, 'max': 10, 'default': 0},
        'num_outbound_cmds': {'type': 'numeric', 'min': 0, 'max': 10, 'default': 0},
        'is_host_login': {'type': 'binary'},
        'is_guest_login': {'type': 'binary'},
        'count': {'type': 'numeric', 'min': 0, 'max': 500, 'default': 1},
        'srv_count': {'type': 'numeric', 'min': 0, 'max': 500, 'default': 1},
        'serror_rate': {'type': 'float', 'min': 0.0, 'max': 1.0, 'default': 0.0},
        'srv_serror_rate': {'type': 'float', 'min': 0.0, 'max': 1.0, 'default': 0.0},
        'rerror_rate': {'type': 'float', 'min': 0.0, 'max': 1.0, 'default': 0.0},
        'srv_rerror_rate': {'type': 'float', 'min': 0.0, 'max': 1.0, 'default': 0.0},
        'same_srv_rate': {'type': 'float', 'min': 0.0, 'max': 1.0, 'default': 1.0},
        'diff_srv_rate': {'type': 'float', 'min': 0.0, 'max': 1.0, 'default': 0.0},
        'srv_diff_host_rate': {'type': 'float', 'min': 0.0, 'max': 1.0, 'default': 0.0},
        'dst_host_count': {'type': 'numeric', 'min': 0, 'max': 255, 'default': 1},
        'dst_host_srv_count': {'type': 'numeric', 'min': 0, 'max': 255, 'default': 1},
        'dst_host_same_srv_rate': {'type': 'float', 'min': 0.0, 'max': 1.0, 'default': 1.0},
        'dst_host_diff_srv_rate': {'type': 'float', 'min': 0.0, 'max': 1.0, 'default': 0.0},
        'dst_host_same_src_port_rate': {'type': 'float', 'min': 0.0, 'max': 1.0, 'default': 1.0},
        'dst_host_srv_diff_host_rate': {'type': 'float', 'min': 0.0, 'max': 1.0, 'default': 0.0},
        'dst_host_serror_rate': {'type': 'float', 'min': 0.0, 'max': 1.0, 'default': 0.0},
        'dst_host_srv_serror_rate': {'type': 'float', 'min': 0.0, 'max': 1.0, 'default': 0.0},
        'dst_host_rerror_rate': {'type': 'float', 'min': 0.0, 'max': 1.0, 'default': 0.0},
        'dst_host_srv_rerror_rate': {'type': 'float', 'min': 0.0, 'max': 1.0, 'default': 0.0}
    }
    
    # Split features into two columns for better layout
    feature_names = list(feature_definitions.keys())
    mid_point = len(feature_names) // 2
    
    with col1:
        st.write("### Basic Connection Features")
        for feature in feature_names[:mid_point]:
            config = feature_definitions[feature]
            
            if config['type'] == 'categorical':
                single_row[feature] = st.selectbox(f"{feature}", config['options'])
            elif config['type'] == 'binary':
                single_row[feature] = st.selectbox(f"{feature}", [0, 1])
            elif config['type'] == 'numeric':
                single_row[feature] = st.number_input(
                    f"{feature}", 
                    min_value=config['min'], 
                    max_value=config['max'], 
                    value=config['default']
                )
            elif config['type'] == 'float':
                single_row[feature] = st.number_input(
                    f"{feature}", 
                    min_value=config['min'], 
                    max_value=config['max'], 
                    value=config['default'],
                    format="%.6f"
                )
    
    with col2:
        st.write("### Traffic & Host Features")
        for feature in feature_names[mid_point:]:
            config = feature_definitions[feature]
            
            if config['type'] == 'categorical':
                single_row[feature] = st.selectbox(f"{feature}", config['options'])
            elif config['type'] == 'binary':
                single_row[feature] = st.selectbox(f"{feature}", [0, 1])
            elif config['type'] == 'numeric':
                single_row[feature] = st.number_input(
                    f"{feature}", 
                    min_value=config['min'], 
                    max_value=config['max'], 
                    value=config['default']
                )
            elif config['type'] == 'float':
                single_row[feature] = st.number_input(
                    f"{feature}", 
                    min_value=config['min'], 
                    max_value=config['max'], 
                    value=config['default'],
                    format="%.6f"
                )
    

    if st.button("🔍 Predict Single Record", key="single_predict"):
        with st.spinner("Making prediction..."):
            try:
                df_single = pd.DataFrame([single_row])
                model, num_classes, input_dim = load_model(model_type, f"saved_model_{model_type}.pt", device)
                result = predict_data(df_single, model, device, label_encoder)
                
                st.write("### 🎯 Prediction Result")
                prediction = result[0]
                if prediction == "normal":
                    st.success(f"✅ **Prediction: {prediction}** - No intrusion detected")
                else:
                    st.error(f"🚨 **Prediction: {prediction}** - Potential intrusion detected!")
                    
            except Exception as e:
                st.error(f"Prediction failed: {e}")

with tab3:
    st.header("Live Network Capture")
    st.info("Capture live network traffic and analyze it for intrusions")
    
    # Add Windows-specific help
    current_status = st.session_state.capture.get_status()
    if "Npcap" in current_status or "winpcap" in current_status.lower():
        st.warning("⚠️ **Windows Users**: Install Npcap from https://nmap.org/npcap/ for real packet capture, or use simulation mode below.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Get available interfaces
        interfaces = get_network_interfaces()
        selected_interface = st.selectbox("Select Network Interface", interfaces)
        st.info("💡 Try 'any' if other interfaces don't work. You may need admin/root privileges.")
        
        capture_duration = st.slider("Capture Duration (seconds)", 1, 60, 10)
        
        capture_col1, capture_col2 = st.columns(2)
        
        with capture_col1:
            if st.button("🔴 Start Capture", key="start_capture"):
                if selected_interface:
                    st.session_state.capture.start_capture(selected_interface, capture_duration)
                    st.success(f"Started capturing on {selected_interface} for {capture_duration} seconds...")
                else:
                    st.error("Please select a network interface")
                
        with capture_col2:
            if st.button("⏹️ Stop Capture", key="stop_capture"):
                st.session_state.capture.stop_capture()
                st.info("Capture stopped")
                
        # Add simulation mode for Windows users
        st.markdown("---")
        st.write("### 🎮 Simulation Mode (for testing)")
        st.info("Generate realistic network traffic data for testing the IDS system")
        
        sim_col1, sim_col2 = st.columns(2)
        with sim_col1:
            packet_count = st.slider("Packets to generate", 5, 100, 20)
        with sim_col2:
            if st.button("🎲 Generate Traffic", key="simulate"):
                st.session_state.capture.simulate_traffic(packet_count)
                st.success(f"Generated {packet_count} simulated packets!")
        
        # Add refresh button to update packet count
        if st.button("🔄 Refresh Status"):
            st.rerun()
    
    with col2:
        st.write("### 📊 Capture Status")
        status = st.session_state.capture.get_status()
        packet_count = len(st.session_state.capture.packets)
        
        if st.session_state.capture.capturing:
            st.warning(f"🔴 {status}")
            st.info(f"📦 Packets captured so far: {packet_count}")
        else:
            st.info(f"ℹ️ Status: {status}")
            st.info(f"📦 Total packets captured: {packet_count}")
            
        # Show recent packet info if available
        if packet_count > 0:
            recent_packet = st.session_state.capture.packets[-1]
            st.write("**Latest packet:**")
            st.write(f"- Protocol: {recent_packet.get('protocol_type', 'unknown')}")
            st.write(f"- Service: {recent_packet.get('service', 'unknown')}")
            st.write(f"- Size: {recent_packet.get('src_bytes', 0)} bytes")
    
    # Show captured data and predict
    if st.button("🔍 Analyze Captured Traffic", key="analyze_capture"):
        df_captured = st.session_state.capture.get_packets_as_dataframe()
        
        if df_captured is not None and len(df_captured) > 0:
            st.write("### 📊 Captured Traffic Data")
            st.dataframe(df_captured.head(10))
            
            with st.spinner("Analyzing captured traffic..."):
                try:
                    model, num_classes, input_dim = load_model(model_type, f"saved_model_{model_type}.pt", device)
                    results = predict_data(df_captured, model, device, label_encoder)
                    
                    # Show results
                    results_df = pd.DataFrame({'Packet_ID': range(len(results)), 'Prediction': results})
                    st.write("### 🎯 Traffic Analysis Results")
                    st.dataframe(results_df)
                    
                    # Alert for intrusions
                    intrusion_count = sum(1 for pred in results if pred != "normal")
                    total_packets = len(results)
                    
                    if intrusion_count > 0:
                        st.error(f"🚨 **ALERT**: {intrusion_count} out of {total_packets} packets show potential intrusion activity!")
                        
                        # Show intrusion types
                        intrusion_types = [pred for pred in results if pred != "normal"]
                        intrusion_counts = pd.Series(intrusion_types).value_counts()
                        st.write("### 🔍 Detected Intrusion Types")
                        st.bar_chart(intrusion_counts)
                    else:
                        st.success(f"✅ All {total_packets} packets appear normal - No intrusions detected")
                    
                except Exception as e:
                    st.error(f"Analysis failed: {e}")
        else:
            st.warning("No packets captured yet. Please start a capture first.")

with tab4:
    st.header("PCAP File Analysis")
    st.info("Upload and analyze PCAP files captured by Wireshark")
    
    pcap_file = st.file_uploader("Upload PCAP file", type=["pcap", "pcapng", "cap"])
    
    if pcap_file is not None:
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_file:
            tmp_file.write(pcap_file.read())
            tmp_file_path = tmp_file.name
        
        try:
            # Read and process PCAP file
            df_pcap = read_pcap_file(tmp_file_path)
            
            if df_pcap is not None:
                st.write("### 📊 PCAP File Contents")
                st.write(f"Total packets processed: {len(df_pcap)}")
                st.dataframe(df_pcap.head(10))
                
                if st.button("🔍 Analyze PCAP File", key="analyze_pcap"):
                    with st.spinner("Analyzing PCAP file..."):
                        try:
                            model, num_classes, input_dim = load_model(model_type, f"saved_model_{model_type}.pt", device)
                            results = predict_data(df_pcap, model, device, label_encoder)
                            
                            # Show results
                            results_df = pd.DataFrame({'Packet_ID': range(len(results)), 'Prediction': results})
                            st.write("### 🎯 PCAP Analysis Results")
                            st.dataframe(results_df)
                            
                            # Summary statistics
                            pred_counts = pd.Series(results).value_counts()
                            st.write("### 📈 Detection Summary")
                            
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("Total Packets", len(results))
                                st.metric("Normal Traffic", pred_counts.get("normal", 0))
                            
                            with col2:
                                intrusion_count = len(results) - pred_counts.get("normal", 0)
                                st.metric("Potential Intrusions", intrusion_count)
                                if intrusion_count > 0:
                                    intrusion_rate = (intrusion_count / len(results)) * 100
                                    st.metric("Intrusion Rate", f"{intrusion_rate:.2f}%")
                            
                            # Visualization
                            if len(pred_counts) > 1:
                                st.write("### 📊 Prediction Distribution")
                                st.bar_chart(pred_counts)
                            
                            # Download results
                            csv = results_df.to_csv(index=False)
                            st.download_button(
                                "💾 Download Analysis Results",
                                csv,
                                "pcap_analysis_results.csv",
                                "text/csv"
                            )
                            
                        except Exception as e:
                            st.error(f"Analysis failed: {e}")
            else:
                st.error("Failed to process PCAP file. Please check the file format.")
                
        except Exception as e:
            st.error(f"Error processing PCAP file: {e}")
        
        finally:
            # Clean up temporary file
            if os.path.exists(tmp_file_path):
                os.unlink(tmp_file_path)

