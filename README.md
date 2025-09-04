Intrusion Detection System (IDS) with Wireshark Integration
A comprehensive machine learning-based Intrusion Detection System that supports real-time network traffic analysis, PCAP file processing, and live packet capture integration with Wireshark.
Features
•	Multiple ML Models: CNN, LSTM, and Transformer architectures
•	Live Packet Capture: Real-time network traffic monitoring
•	PCAP File Analysis: Process Wireshark capture files
•	Interactive Web UI: User-friendly Streamlit interface
•	Explainable AI: LIME and SHAP model explanations
•	Simulation Mode: Generate realistic network traffic for testing
Project Structure
project/
├── main.py                 # Model training script
├── ui_with_wireshark.py    # Enhanced UI with Wireshark integration
├── models.py               # CNN, LSTM, Transformer model definitions
├── utils.py                # Data preprocessing utilities
├── explain.py              # XAI explanations (LIME/SHAP)
├── nsl_kdd_cleaned.csv     # NSL KDD Dataset
├── saved_model_*.pt        # Trained model files (generated)
├── label_encoder_*.pkl     # Label encoders (generated)
└── reports/                # XAI explanation outputs (generated)
Installation & Setup
1. Install Python Dependencies
pip install torch torchvision torchaudio
pip install streamlit pandas numpy scikit-learn
pip install scapy matplotlib seaborn
pip install lime shap
pip install joblib cryptography
2. Windows Users - Install Packet Capture Support
For real packet capture on Windows, install Npcap:
•	Download from: https://nmap.org/npcap/
•	Install with default settings
•	Restart your computer after installation
Note: If you skip this step, you can still use the simulation mode for testing.
3. Dataset Preparation
Ensure your dataset CSV file has the following columns (KDD Cup 99 format):
duration, protocol_type, service, flag, src_bytes, dst_bytes, land, wrong_fragment, 
urgent, hot, num_failed_logins, logged_in, num_compromised, root_shell, su_attempted, 
num_root, num_file_creations, num_shells, num_access_files, num_outbound_cmds, 
is_host_login, is_guest_login, count, srv_count, serror_rate, srv_serror_rate, 
rerror_rate, srv_rerror_rate, same_srv_rate, diff_srv_rate, srv_diff_host_rate, 
dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate, 
dst_host_same_src_port_rate, dst_host_srv_diff_host_rate, dst_host_serror_rate, 
dst_host_srv_serror_rate, dst_host_rerror_rate, dst_host_srv_rerror_rate, label
Usage Instructions
Step 1: Train the Models – Provided the trained models
Train all three models (CNN, LSTM, Transformer):
# Train CNN model
python main.py --data dataset.csv --model CNN --epochs 20

# Train LSTM model  
python main.py --data dataset.csv --model LSTM --epochs 20

# Train Transformer model
python main.py --data dataset.csv --model Transformer --epochs 20
What this does:
•	Preprocesses your dataset
•	Trains the selected model
•	Saves model weights (saved_model_*.pt)
•	Saves label encoder (label_encoder_*.pkl)
•	Generates XAI explanations in reports/ folder
•	Displays training metrics and evaluation results
Step 2: Launch the Web Interface
streamlit run ui_with_wireshark.py
For better packet capture permissions:
# Windows (as Administrator)
streamlit run ui_with_wireshark.py

# Linux/Mac (with sudo)
sudo streamlit run ui_with_wireshark.py
Step 3: Use the Web Interface
The web interface provides 4 main tabs:
Upload CSV Tab
•	Upload CSV datasets for batch prediction
•	View data preview and prediction results
•	Download results and visualizations
Single Record Tab
•	Manual entry of network connection features
•	Dropdown menus for categorical data (protocol_type, service, flag)
•	Real-time single prediction results
Live Capture Tab
•	Real Packet Capture: 
o	Select network interface (try "any" first)
o	Set capture duration
o	Analyze captured traffic in real-time
•	Simulation Mode (recommended for testing): 
o	Generate realistic network traffic data
o	Include both normal and attack patterns
o	Perfect for testing without real network access
PCAP File Tab
•	Upload PCAP files from Wireshark
•	Automatic packet processing and feature extraction
•	Batch analysis of captured network sessions
 
Quick Start Guide
Option A: Using Real Dataset
1.	Prepare your CSV dataset with network flow features
2.	Train models: python main.py --data dataset.csv --model CNN
3.	Launch UI: streamlit run ui_with_wireshark.py
4.	Test with CSV upload or single record entry
Option B: Testing with Simulated Data
1.	Train with your dataset (or use a sample dataset)
2.	Launch UI: streamlit run ui_with_wireshark.py
3.	Go to "Live Capture" → "Simulation Mode"
4.	Generate 20-50 packets and analyze them
5.	See real-time intrusion detection results!
Model Training Details
Command Line Arguments:
•	--data: Path to your CSV dataset
•	--model: Choose from CNN, LSTM, or Transformer
•	--epochs: Number of training epochs (default: 10)
Training Output:
•	Model files: saved_model_[MODEL].pt
•	Label encoders: label_encoder_[MODEL].pkl
•	Evaluation metrics: Accuracy, Precision, Recall, F1-Score
•	XAI reports: LIME and SHAP explanations in reports/
Network Interfaces Guide
Interface Selection:
•	"any": Captures on all interfaces (recommended first try)
•	Windows: Try "WiFi", "Ethernet", or specific adapter names
•	Linux: Try "eth0", "wlan0", "ens33"
•	Mac: Try "en0", "en1"
Troubleshooting Packet Capture:
1.	Permission Denied: Run as administrator/root
2.	No Packets Captured: Try different interface or use simulation mode
3.	Npcap Error: Install Npcap from https://nmap.org/npcap/
4.	Testing: Use simulation mode to generate test data
Supported Attack Types
The system can detect various network intrusions:
DOS Attacks: neptune, smurf, back, land, pod, teardrop Probe Attacks: ipsweep, portsweep, nmap, satan R2L Attacks: guess_passwd, ftp_write, imap, phf, multihop, warezmaster, warezclient, spy U2R Attacks: buffer_overflow, loadmodule, rootkit
Demo
# 1. Train a model 
python main.py --data nsl_kdd_cleaned.csv --model CNN --epochs 10

# 2. Launch the interface
streamlit run ui_with_wireshark.py

# 3. In the web interface:
- Go to "Live Capture" tab
- Click "Generate Traffic" (simulation mode)
- Click "Analyze Captured Traffic"
- See real-time intrusion detection results!
________________________________________

