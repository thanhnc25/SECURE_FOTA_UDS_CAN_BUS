# Gateway FOTA - ESP32 Intelligent Bridge

**Supported Targets:** ESP32-WROOM-32 (tested), ESP32-C3, ESP32-S3

---

## 📋 Overview

**Gateway FOTA** is an ESP32-based intelligent bridge connecting cloud/LAN firmware distribution to automotive CAN bus networks. It implements **ISO 14229-1 (UDS)** client and **ISO 15765-2 (CAN-TP)** transport protocols with **security pre-validation** firewall.

### Key Role
Acts as a **protocol translator** and **security checkpoint** between high-speed networks (Wi-Fi/Ethernet) and resource-constrained automotive CAN bus (125 kbps).

---

## 🎯 Key Features

### 1. Multi-Interface Connectivity

#### Network Interfaces
- **Wi-Fi Client (TLS/SSL)**  
  HTTPS downloads from Firebase Cloud Storage with TLS 1.2 certificate validation
  
- **Ethernet (W5500 Module)**  
  TCP firmware transfer + UDP discovery protocol for local network deployment
  
- **CAN Bus (SN65HVD230)**  
  ISO 15765-2 transport layer, 125 kbps bitrate, 11-bit identifiers

### 2. Security Firewall (Pre-Validation)

**Purpose:** Prevent corrupted/malicious firmware from reaching CAN bus

**Validation Pipeline:**
```
1. Download firmware (HTTPS/TCP)
2. Parse 228-byte FOTA header
3. Verify SHA-256 hash (encrypted firmware)
   → FAIL: Reject, request retry
4. Verify ECDSA P-256 signature  
   → FAIL: Reject, log security event
5. PASS: Forward to CAN bus via UDS
```

**Benefits:**
- Early corruption detection (before CAN transmission)
- CAN bus flood protection
- Defense-in-depth architecture

### 3. UDS Client (ISO 14229-1)

**Implemented Services:**

| SID | Service | Response Time |
|-----|---------|---------------|
| `0x10` | Diagnostic Session Control | ~50ms |
| `0x22` | Read Data By Identifier | ~10ms |
| `0x34` | Request Download | ~20ms |
| `0x36` | Transfer Data | ~150ms/block |
| `0x37` | Request Transfer Exit | ~5200ms |

**NRC 0x78 Keep-Alive Protocol:**
- Handles Response Pending messages from STM32
- Retries up to 10 times (30s total timeout)
- Prevents timeout during 5.2s STM32 verification

### 4. CAN-TP Client (ISO 15765-2)

**Frame Handling:**
- **First Frame (FF):** Total length indicator
- **Consecutive Frame (CF):** 7-byte payload/frame
- **Flow Control (FC):** BS=8, STmin=10ms

**Transfer Performance:**
- 7524-byte firmware: ~16 seconds
- Bottleneck: STmin=10ms mandatory delay

### 5. LVGL Touch UI

**Features:**
- Real-time progress bar (0-100%)
- CAN-TP throughput meter
- Error logging (last 10 events)
- Network status indicators

---

## 📦 File Structure

```
Gateway_FOTA_ESP32/
├── main/
│   ├── main.cpp                      # 🔒 Application entry point
│   ├── CMakeLists.txt                # Component build config
│   ├── include/
│   │   ├── uds/
│   │   │   └── uds_client.hpp        # ⭐ UDS protocol interface
│   │   ├── isotp/
│   │   │   └── isotp_client.hpp      # ⭐ CAN-TP transport layer
│   │   ├── network/
│   │   │   └── udp_discovery.hpp     # ⭐ UDP device discovery
│   │   ├── fota/
│   │   │   ├── fota_protocol.hpp     # ⭐ FOTA header definitions
│   │   │   ├── fota_security.hpp     # ⭐ SHA-256 + ECDSA verification
│   │   │   └── version_checker.hpp   # ⭐ Metadata comparison
│   │   └── crypto/
│   │       └── public_key.h          # 🔒 ECDSA public key
│   └── src/
│       ├── uds_client.cpp            # ⭐ UDS client implementation
│       ├── isotp_client.cpp          # ⭐ CAN-TP frame handling
│       ├── udp_discovery.cpp         # ⭐ UDP broadcast protocol
│       ├── fota_security.cpp         # ⭐ Pre-validation firewall
│       ├── version_checker.cpp       # ⭐ Firebase metadata parser
│       ├── wifi_station.cpp          # 🔒 Wi-Fi client
│       └── fota_manager.cpp          # 🔒 Main orchestration
├── CMakeLists.txt                    # Project configuration
├── sdkconfig                         # ESP32 hardware config
└── README.md                         # This file
```

**Legend:**  
⭐ = Whitelisted (public showcase)  
🔒 = Private (protected by .gitignore)

---

## 🔧 Installation

### Prerequisites

#### Hardware
- **ESP32-DevKitC** (ESP32-WROOM-32 module)
- **W5500 Ethernet Module** (SPI interface)
- **SN65HVD230 CAN Transceiver** (3.3V logic)
- **ILI9341 TFT Display** (320x240, SPI + touch)

#### Software
- **ESP-IDF v5.3.4** (tested version)
- **Python 3.8+** (for esptool.py)
- **Git** (for component management)

### Hardware Connections

**CAN Bus (SN65HVD230):**
| ESP32 Pin | CAN Transceiver |
|-----------|----------------|
| GPIO 21 (TX) | CTX |
| GPIO 22 (RX) | CRX |
| 3.3V | VCC |
| GND | GND |
| - | CANH → CAN Bus H |
| - | CANL → CAN Bus L |

**Note:** 120Ω termination resistor required between CANH and CANL

**Ethernet (W5500):**
| ESP32 Pin | W5500 |
|-----------|-------|
| GPIO 23 | MOSI |
| GPIO 19 | MISO |
| GPIO 18 | SCK |
| GPIO 5 | CS |
| GPIO 26 | RST |

**TFT Display (ILI9341):**
| ESP32 Pin | ILI9341 |
|-----------|---------|
| GPIO 23 | MOSI |
| GPIO 19 | MISO |
| GPIO 18 | SCK |
| GPIO 15 | CS |
| GPIO 2 | DC |
| GPIO 4 | RST |
| GPIO 27 | BL (Backlight) |

### Setup Steps

1. **Install ESP-IDF**
   ```bash
   git clone --recursive https://github.com/espressif/esp-idf.git
   cd esp-idf
   ./install.sh esp32
   . ./export.sh
   ```

2. **Build Project**
   ```bash
   cd Gateway_FOTA_ESP32
   idf.py build
   ```

3. **Flash & Monitor**
   ```bash
   idf.py -p /dev/ttyUSB0 flash monitor
   ```
   (Windows: `-p COM3`)

---

## 🚀 Usage

### OTA Update (Cloud Mode)

```
1. ESP32 auto-checks Firebase (every 60s)
   └─> GET metadata.json

2. Compare versions
   └─> v1.2.0 (current) vs v1.2.1 (available)

3. User confirms update (touch LCD)

4. Download firmware (HTTPS)
   └─> 7524 bytes in ~2 seconds

5. Pre-validation
   ├─> SHA-256 verification ✓
   └─> ECDSA verification ✓

6. UDS transfer to STM32
   ├─> 0x10: Enter programming mode
   ├─> 0x34: Request Download
   ├─> 0x36: Transfer Data (8 blocks)
   ├─> 0x37: Request Transfer Exit
   │   ├─> NRC 0x78 (Response Pending)
   │   ├─> NRC 0x78 (keep-alive)
   │   ├─> NRC 0x78 (keep-alive)
   │   └─> 0x77 (Positive response)
   └─> Success! ECU will reset
```

### OTA Update (LAN Mode)

```
1. Python FOTA Manager starts TCP server (port 5000)

2. ESP32 UDP discovery
   └─> Broadcast: "FOTA_DISCOVER" (port 5001)

3. Python responds
   └─> "FOTA_SERVER:192.168.1.50:5000:v1.2.1"

4. TCP download
   └─> 7524 bytes in ~200ms

5. Pre-validation + UDS transfer (same as cloud)
```

---

## 🔐 Security Architecture

### NRC 0x78 Keep-Alive Implementation

**Problem:** STM32 verification = 5.2s, ESP32 timeout = 3s

**Solution:**
```cpp
// uds_client.cpp
esp_err_t request_transfer_exit() {
    uint32_t nrc78_count = 0;
    
    while (true) {
        err = isotp_recv(&response, 3000);
        
        if (response[0] == 0x7F && response[2] == 0x78) {
            nrc78_count++;
            if (nrc78_count > 10) {
                return ESP_ERR_TIMEOUT;  // 30s total
            }
            ESP_LOGI(TAG, "NRC 0x78 received (%u/10)", nrc78_count);
            continue;  // Reset timeout, wait for next message
        }
        
        if (response[0] == 0x77) {
            return ESP_OK;  // Success
        }
        
        break;
    }
}
```

**Result:** 5.2s STM32 verification completes successfully

---

## 📊 Performance Metrics

| Interface | Payload | Time | Throughput |
|-----------|---------|------|------------|
| HTTPS | 7524 bytes | ~2s | ~30 Kbps |
| TCP (LAN) | 7524 bytes | ~200ms | 300 Kbps |
| CAN-TP | 7524 bytes | ~16s | 583 bytes/s |

**Memory Usage:**
- Flash: 1250 KB
- RAM: 145 KB

---

## 🧪 Testing

### Unit Test: ECDSA Verification

```cpp
void test_ecdsa() {
    uint8_t hash[32] = {...};  // Known-good SHA-256
    uint8_t signature[64] = {...};  // From Python
    
    bool result = ecdsa_verify(hash, signature, public_key);
    assert(result == true);
    ESP_LOGI(TAG, "ECDSA test PASSED");
}
```

### Integration Test: End-to-End OTA

```bash
# 1. Flash ESP32 + STM32 bootloader
# 2. Start Python FOTA Manager (LAN mode)
# 3. ESP32 auto-discovers server
# 4. Trigger update from LCD
# 5. Verify STM32 UART: "APPLICATION START v1.2.1"
```

---

## 🐛 Troubleshooting

**Issue: "ECDSA verification failed"**

Check public key:
```bash
# Copy from Python server
cp ../SERVER_PYTHON/keys/public_key.h main/include/crypto/

# Rebuild
idf.py build flash
```

**Issue: "UDS timeout during 0x37"**

Check NRC 0x78 logs:
```
I (12500) UDS: NRC 0x78 received (1/10)
I (15600) UDS: NRC 0x78 received (2/10)
I (18700) UDS: NRC 0x78 received (3/10)
I (21800) UDS: 0x77 positive response
```

If timeout occurs: Increase `max_nrc78_retries` in `uds_client.cpp`

**Issue: "CAN bus not active"**

Check hardware:
1. CAN transceiver power (3.3V)
2. 120Ω termination resistor
3. GPIO configuration (TX=21, RX=22)

---

## 📚 API Reference

### UDS Client

```cpp
class UDSClient {
public:
    esp_err_t diagnostic_session_control(uint8_t session_type);
    esp_err_t read_data_by_identifier(uint16_t did, std::vector<uint8_t>* data);
    esp_err_t request_download(uint32_t address, uint32_t size);
    esp_err_t transfer_data(uint8_t block_seq, const uint8_t* data, size_t len);
    esp_err_t request_transfer_exit();
};
```

### FOTA Security

```cpp
namespace fota {
    bool validate_package(const uint8_t* package, size_t size);
    bool verify_sha256(const uint8_t* data, size_t len, const uint8_t* expected_hash);
    bool verify_ecdsa(const uint8_t* hash, const uint8_t* signature);
}
```

---

## 📄 License

**Academic Project** - Educational and portfolio demonstration

---

## 👤 Author

**Embedded Systems Engineer**  
Specialization: Automotive Protocols, Network Security, UDS/CAN-TP
