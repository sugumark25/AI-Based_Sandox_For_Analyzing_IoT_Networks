# AI-Based Sandbox for Analyzing Iot Network

This project detects abnormal network behavior in IoT systems using a hybrid approach of an ESP32 edge device and machine learning analysis in a Python backend, visualized in a React dashboard. **Includes automated attack blocking with real-time command execution!**

## 🎯 Key Features
- ✅ **Real-time Anomaly Detection** - ML models on edge + backend
- ✅ **Attack Classification** - DDoS, Port Scans, ICMP Sweeps, Botnet C2
- ✅ **Automated Attack Blocking** - Generates & executes blocking commands instantly
- ✅ **Reliable Command Storage** - SQLite persistence for audit trail
- ✅ **Live Dashboard** - React UI with attack & blocking metrics
- ✅ **MQTT Integration** - Secure device communication

## 📊 System Architecture
- **Edge Device** (C++/ESP32): Captures packets → Local inference → Executes blocks
- **Backend API** (Python/Flask): ML analysis → Attack classification → Command generation
- **Database** (SQLite): Command persistence, history, audit trail
- **Dashboard** (React): Real-time metrics, attack visualization, block statistics
- **MQTT Broker**: Device-to-backend messaging for commands & telemetry

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 14+
- Arduino IDE with ESP32 support
- MQTT Broker (mosquitto or equivalent)
- PubSubClient and ArduinoJson libraries

### 1. Backend Setup (Python)
The backend runs ML models, analyzes attacks, and manages blocking commands via REST API and MQTT.

### Initial Setup
1. CD into the backend directory:
   ```bash
   cd backend
   ```
2. Create and activate a Virtual Environment (Windows):
   ```bash
   python -m venv venv
   .\venv\Scripts\activate
   ```
3. Install Dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Backend Server
Once the virtual environment is activated, simply start the server:
```bash
python server.py
```
*Note: This server handles REST API calls on `http://localhost:5000` and Socket.IO for real-time dashboard updates.*

### 2. Frontend Setup (React)
The frontend provides a real-time dashboard showing attack detection, blocking statistics, and system health.

### Initial Setup
1. Open a **new** terminal window and CD into the frontend directory:
   ```bash
   cd frontend
   ```
2. Install package dependencies:
   ```bash
   npm install
   ```

### Running the Frontend Dashboard
Start the React development server:
```bash
npm start
```
*The dashboard will automatically open in your browser at `http://localhost:3000`.*

### 3. ESP32 Edge Device Setup (C++)
The ESP32 captures network traffic in real-time, runs local ML inference, receives blocking commands via MQTT, and executes blocks by dropping packets from blocked sources. 

### Prerequisites
- Install **Arduino IDE**.
- Add [ESP32 support](https://randomnerdtutorials.com/installing-the-esp32-board-in-arduino-ide-windows-instructions/) to Arduino IDE.
- Install these Arduino libraries via the Library Manager (`Sketch > Include Library > Manage Libraries...`):
   - `PubSubClient` (by Nick O'Leary)
   - `ArduinoJson` (by Benoit Blanchon)

### Steps to Run
1. Open the file `edge_device/edge_device.ino` in Arduino IDE.
2. In `wifi_setup.ino`, update the placeholders for your network:
   - `const char* ssid = "YOUR_WIFI_SSID";`
   - `const char* password = "YOUR_WIFI_PASSWORD";`
   - `const char* backend_host = "YOUR_BACKEND_IP";` (Replace with the local IP address of your machine running the Python backend, e.g., `192.168.1.5`).
3. Connect your ESP32 to your PC via USB.
4. Select the correct COM Port and Board (`DOIT ESP32 DEVKIT V1` or similar) in the `Tools` menu.
5. Click **Upload**.
6. Open the **Serial Monitor** (115200 baud) to view the live logs from the ESP32.

---

## 🔒 Attack Blocking System

### How It Works
1. **ESP32 detects anomalies** via packet analysis & local ML inference
2. **Backend analyzes the attack** → Classification (DDoS, PortScan, etc.)
3. **Command generated** → Decision: Should we block? What action?
4. **Command stored** in SQLite database (PENDING state)
5. **ESP32 polls backend** for pending commands
6. **Block executed** on ESP32 → Packets from attacker source dropped
7. **Confirmation sent** back to backend (EXECUTED state)

### Attack Types Detected & Blocked
- 🔴 **DDoS**: High packet rate + massive traffic volume
- 🟠 **Port Scan**: Low packets + high connection rejections  
- 🟡 **ICMP Sweep**: ICMP packets with rejection patterns
- 🔵 **Botnet C2**: Bi-directional traffic + high variance
- ⚪ **Generic Attack**: Anomalous patterns not fitting other categories

### Blocking Actions
- `block_ip` - Drop all packets from source IP
- `block_proto` - Block specific protocol (TCP/UDP/ICMP) from source
- `block_port` - Drop traffic to specific destination port
- `block_connection` - Block specific source:port combination
- `drop_traffic` - Drop based on traffic characteristics

### Configuration
Edit `edge_device/src/config.h`:
```cpp
#define MAX_BLOCKS 10              // Max concurrent blocks (default 10)
#define USE_MQTT true              // Enable MQTT for commands
#define MQTT_BROKER_HOST "192.168.137.1"
#define MQTT_BROKER_PORT 1883
```

### Monitoring Blocks
Check ESP32 heartbeat output for:
```
--- Blocking Status ---
Active blocks: 2
Packets dropped: 342
Commands received: 3
Commands failed: 0
```

---

## 📚 Documentation

### For Developers
- **[BLOCKING_SYSTEM_GUIDE.md](BLOCKING_SYSTEM_GUIDE.md)** - Complete architecture, API reference, examples
- **[IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)** - What was implemented and where

### For Operations
- **[BLOCKING_SYSTEM_CHECKLIST.md](BLOCKING_SYSTEM_CHECKLIST.md)** - Deployment, testing, troubleshooting

### Backend Files
- `backend/block_manager.py` - Command persistence layer (SQLite)
- `backend/attack_analyzer.py` - Attack classification logic
- `backend/routes.py` - REST API endpoints for blocking commands

### ESP32 Files  
- `edge_device/src/block_command.h` - Blocking execution logic
- `edge_device/src/mqtt_client.h` - MQTT command subscription
- `edge_device/src/main.cpp` - Command processing loop

---

## 🔧 API Endpoints

### Create Blocking Command
```http
POST /api/commands/create
Content-Type: application/json

{
  "device_id": "ESP32E-01",
  "action": "block_ip",
  "target": "192.168.1.100",
  "reason": "DDoS Attack",
  "attack_data": {...}
}
```

### Get Pending Commands (ESP32 polling)
```http
GET /api/commands/pending/ESP32E-01
```

### Confirm Command Execution
```http
POST /api/commands/cmd_abc123/confirm
{
  "status": "executed",
  "duration_sec": 0.045
}
```

### Get Blocking History
```http
GET /api/blocks/history?device_id=ESP32E-01&limit=50
```

### Blocking Summary
```http
GET /api/blocks/summary
```

For complete API documentation, see `BLOCKING_SYSTEM_GUIDE.md`.

---

## 📊 System Workflow

```
┌─ ESP32 Edge Device ─────────────────────┐
│  • Packet capture (WiFi sniffer)        │
│  • Local Z-score anomaly detection      │
│  • TinyML model inference               │
│  • Pattern caching (deduplication)      │
│  • Sends flows to backend               │
└─────────────────┬───────────────────────┘
                  │ MQTT: Flows + Features
                  ▼
┌─ Backend Analysis ──────────────────────┐
│  • XGBoost model inference              │
│  • Autoencoder reconstruction error     │
│  • Attack classification & severity     │
│  • Confidence scoring                   │
│  • Decision: Block or Not?              │
└─────────────────┬───────────────────────┘
                  │ If Confidence > 70%
                  ▼
┌─ Command Generation & Storage ──────────┐
│  • Generate action (block_ip, etc.)     │
│  • Store in SQLite DB (PENDING)         │
│  • Create audit trail entry             │
└─────────────────┬───────────────────────┘
                  │ MQTT: Blocking command
                  ▼
┌─ ESP32 Execution ───────────────────────┐
│  • Receive command via MQTT             │
│  • Parse JSON & validate                │
│  • Add to packet filter list            │
│  • Drop packets in real-time            │
│  • Confirm execution (EXECUTED)         │
└─────────────────────────────────────────┘
```

---

## ⚙️ Testing & Validation

### Backend Health Check
```bash
curl http://localhost:5001/api/health
```

### Create Test Attack Command
```bash
curl -X POST http://localhost:5001/api/commands/create \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "ESP32E-01",
    "action": "block_ip",
    "target": "192.168.1.100",
    "reason": "Test Attack",
    "attack_data": {}
  }'
```

### Monitor Blocking Activity
```bash
# Via Dashboard: Check blocking statistics panel
# Via Logs: tail -f backend/logs/blocking.log
# Via Database: sqlite3 backend/data/blocking_commands.db "SELECT * FROM blocking_commands;"
```

---

## 🛡️ Security Considerations

- ✅ Commands validated before execution (JSON schema)
- ✅ SQLite database stores full command history
- ✅ Thread-safe database operations with locks
- ✅ Max 10 concurrent blocks to prevent memory exhaustion
- ✅ Automatic cleanup of old records after 7 days
- ✅ MQTT authentication support (configurable)
- ✅ Commands signed and rate-limited (future enhancement)

---

## 🚀 Future Enhancements

- [ ] Block TTL (Time-To-Live) - Auto-unblock after timeout
- [ ] Geographic blocking - Block by country/AS
- [ ] HTTP polling fallback - Alternative to MQTT
- [ ] Reputation system - Track serial attackers
- [ ] ML feedback loop - Optimize thresholds
- [ ] Distributed blocking - Sync across multiple ESP32s
- [ ] Real-time block events - WebSocket streaming
- [ ] Machine learning based tuning - Auto-adjust thresholds

---

## 🐛 Troubleshooting

### Backend Issues
- **Models not found**: Run `python backend/train.py`
- **MQTT connection fails**: Check broker is running (`mosquitto`)
- **Commands stuck in PENDING**: Verify ESP32 polls `/api/commands/pending/{device_id}`

### ESP32 Issues
- **Commands not received**: Check MQTT subscription to `iot/commands/{device_id}`
- **Blocks not applied**: Verify `blockCount < MAX_BLOCKS`
- **MQTT connection fails**: Check `MQTT_BROKER_HOST` and `MQTT_BROKER_PORT` in config.h

### Database Issues
- **Database locked**: Stop backend, ensure only one instance running
- **No commands in history**: Check blocking thresholds, run tests

For detailed troubleshooting, see `BLOCKING_SYSTEM_CHECKLIST.md`.

---

## 📝 Project Structure

```
.
├── backend/
│   ├── app.py                    # Main entry point
│   ├── routes.py                 # REST API endpoints (with blocking)
│   ├── block_manager.py          # Command persistence layer
│   ├── attack_analyzer.py        # Attack classification engine
│   ├── anomaly_detector.py       # ML models (XGBoost + AE)
│   ├── mqtt_subscriber.py        # MQTT listener
│   ├── realtime_collector.py     # CSV data storage
│   ├── models/                   # Trained ML models
│   ├── dataset/                  # Training datasets
│   ├── data/                     # SQLite database (auto-created)
│   └── requirements.txt
│
├── edge_device/	
│   ├── platformio.ini            # PlatformIO config
│   └── src/
│       ├── main.cpp              # Main ESP32 loop (with blocking)
│       ├── config.h              # WiFi, MQTT, ML config
│       ├── packet_monitor.h      # Real-time packet capture
│       ├── tinyml_inference.h    # TinyML model inference
│       ├── mqtt_client.h         # MQTT (updated for commands)
│       ├── block_command.h       # Blocking execution logic
│       ├── wifi_setup.h
│       ├── sensor_reader.h
│       └── ...
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── components/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── AlertsPanel.jsx
│   │   │   ├── ModelMetrics.jsx
│   │   │   └── ...
│   │   └── services/
│   │       └── api.js
│   ├── package.json
│   └── ...
│
├── BLOCKING_SYSTEM_GUIDE.md      # Complete blocking documentation
├── BLOCKING_SYSTEM_CHECKLIST.md  # Deployment checklist
├── IMPLEMENTATION_SUMMARY.md     # Implementation overview
└── README.md                     # This file
```

---

## 📄 License & Attribution

This project combines edge AI anomaly detection with backend ML analysis for IoT security.

---

## ✅ Status

- [x] Real-time anomaly detection
- [x] ML model training & inference
- [x] MQTT communication
- [x] Live dashboard
- [x] **Attack blocking system** ← NEW!
- [x] Command persistence (SQLite)
- [x] API endpoints for blocking
- [x] ESP32 command execution
- [x] Audit trail & history
- [ ] Production deployment
- [ ] Advanced features (TTL, geo-blocking, etc.)