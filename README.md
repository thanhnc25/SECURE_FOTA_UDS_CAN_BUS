# Secure FOTA System for Automotive ECUs via UDS/CAN Bus

[![Platform](https://img.shields.io/badge/Platform-STM32%20%7C%20ESP32-blue)](https://github.com)
[![Protocol](https://img.shields.io/badge/Protocol-ISO%2014229--1%20%7C%20ISO%2015765--2-green)](https://github.com)
[![Security](https://img.shields.io/badge/Security-ECDSA%20P--256%20%7C%20AES--128-red)](https://github.com)
[![License](https://img.shields.io/badge/License-Academic-orange)](https://github.com)

A production-grade **Secure Firmware Over-The-Air (FOTA)** update system for automotive Electronic Control Units (ECUs), implementing **ISO 14229-1 (UDS)** and **ISO 15765-2 (CAN-TP)** diagnostic protocols with **multi-layer cryptographic protection** (dual ECDSA signatures, AES-128-CBC encryption, SHA-256 integrity verification).

---

## 📌 Project Overview

This system demonstrates a complete **cloud-to-embedded** OTA update pipeline for automotive ECUs, featuring:

- **Multi-Layer Security:** AES-128 encryption, dual ECDSA P-256 signatures, SHA-256 hashing
- **Automotive Standards:** ISO 14229-1 (UDS), ISO 15765-2 (CAN-TP), ISO 11898 (CAN Physical)
- **Fail-Safe Architecture:** Dual-slot flash management, power-loss recovery, secure boot
- **Hybrid Distribution:** Cloud (Firebase) + Local Network (TCP/UDP)
- **Real-Time Protocols:** NRC 0x78 keep-alive, CAN-TP flow control

### System Components

1. **FOTA Manager (Python)** - Cryptographic authority, firmware signing, cloud/LAN distribution
2. **Gateway (ESP32)** - Protocol bridge, security firewall, UDS client orchestrator
3. **Target ECU Bootloader (STM32)** - Verify-then-decrypt pipeline, dual-slot manager, secure boot
4. **Target ECU Application (STM32)** - User firmware with version reporting, CAN communication

---

## 🎨 System Architecture

![System Architecture](Diagrams/SYSTEM%20ARCHITECTURE.drawio.png)

### Multi-Layer Security Flow

The architecture implements **Defense-in-Depth** with security checks at every transition point:

**Layer 1: Python Server (Signing Center)**
- Generate SHA-256 hashes (plaintext + encrypted firmware)
- Create dual ECDSA signatures (secure boot + OTA transport)
- AES-128-CBC encryption with random IV
- Package 228-byte FOTA header + encrypted payload

**Layer 2: ESP32 Gateway (Security Firewall)**
- Download firmware via HTTPS (TLS 1.2) or TCP (LAN)
- Pre-validation: SHA-256 + ECDSA verification
- Reject corrupted firmware before CAN transmission
- Protocol translation: TCP/HTTP → UDS/CAN-TP

**Layer 3: STM32 ECU (Root of Trust)**
- 5-stage verification pipeline (SHA-256 → ECDSA → AES → SHA-256 → ECDSA)
- Dual-slot atomic flash management
- Power-loss recovery via backup registers
- Secure boot with mandatory signature verification

---

## 🔄 OTA Update Flow

![OTA Flow](Diagrams/OTA%20FLOW.drawio.png)

### Complete Update Sequence

**Phase 1: Firmware Preparation (Python)**
```
1. Load plaintext firmware (7284 bytes)
2. SHA-256(plaintext) → original_sha256
3. ECDSA-Sign(original_sha256) → plaintext_signature  [Secure Boot]
4. AES-128-CBC-Encrypt(plaintext) → encrypted (7296 bytes)
5. SHA-256(encrypted) → sha256
6. ECDSA-Sign(sha256) → signature  [OTA Transport]
7. Create 228-byte header + encrypted firmware = 7524 bytes
```

**Phase 2: Distribution (Firebase/LAN)**
```
Cloud Mode:  Upload to Firebase Storage → ESP32 HTTPS download
LAN Mode:    TCP server (port 5000) + UDP beacon (port 5001)
```

**Phase 3: Pre-Validation (ESP32)**
```
1. Parse 228-byte FOTA header
2. Verify SHA-256 (encrypted firmware)
3. Verify ECDSA signature (encrypted)
4. If PASS: Forward to STM32 via UDS
   If FAIL: Reject, prevent CAN bus flooding
```

**Phase 4: UDS Transfer (ESP32 → STM32)**
```
UDS 0x10: Enter programming session
UDS 0x34: Request Download (7524 bytes, negotiate block size)
UDS 0x36: Transfer Data (8 blocks × 1024 bytes via CAN-TP)
UDS 0x37: Request Transfer Exit (trigger verification)
```

**Phase 5: Verification & Flash (STM32)**
```
1. Verify SHA-256 (encrypted) - 21ms
2. Send NRC 0x78 (keep-alive)
3. Verify ECDSA (encrypted) - 611ms
4. Send NRC 0x78
5. AES-128-CBC decrypt - 1562ms (stream-based, 256-byte chunks)
6. Verify SHA-256 (plaintext) - 21ms
7. Send NRC 0x78
8. Verify ECDSA (plaintext) - 611ms
9. Erase Slot A - 800ms
10. Copy Slot B → Slot A - 2000ms (atomic, power-loss safe)
11. Update metadata - 100ms
12. Send UDS 0x77 (positive response)
13. Reset MCU → Boot into new firmware
```

**Total Time:** ~23 seconds (CAN-TP transfer dominates)

---

## 🗺️ Memory Map Layout

![Memory Map](Diagrams/MEMORY%20MAP%20LAYOUT%20STM32.drawio.png)

### STM32F103C8T6 Flash Organization (64KB)

```
┌─────────────────────────────────────────────────────────────┐
│ 0x08000000 - 0x080077FF (30KB) │ BOOTLOADER               │
│ - Write-protected                                           │
│ - CAN-TP/UDS server, crypto engine, secure boot logic      │
├─────────────────────────────────────────────────────────────┤
│ 0x08007800 - 0x08007BFF (1KB)  │ METADATA A (Active)      │
│ - FOTA header: 228 bytes (dual signatures + hashes)        │
│ - Used by secure boot to validate Slot A                   │
├─────────────────────────────────────────────────────────────┤
│ 0x08007C00 - 0x0800BBFF (16KB) │ SLOT A (Active Firmware) │
│ - Currently running application                             │
│ - Verified at every boot (SHA-256 + ECDSA)                  │
│ - Updated atomically from Slot B                            │
├─────────────────────────────────────────────────────────────┤
│ 0x0800BC00 - 0x0800BFFF (1KB)  │ METADATA B (Download)    │
│ - Received via UDS 0x36 during OTA                          │
├─────────────────────────────────────────────────────────────┤
│ 0x0800C000 - 0x0800FFFF (16KB) │ SLOT B (Staging Area)    │
│ - OTA download target (receives encrypted firmware)         │
│ - Decrypted in-place, then copied to Slot A                 │
└─────────────────────────────────────────────────────────────┘
```

**Dual-Slot Benefits:**
- Zero downtime: App runs from Slot A while Slot B receives update
- Fail-safe: If OTA fails, Slot A remains intact (no rollback needed)
- Power-loss recovery: Interrupted copy can resume from checkpoint

---

## 📡 CAN-TP Sequence Diagram

![CAN-TP Sequence](Diagrams/CAN-TP%20SEQUENCE%20DIAGRAM.drawio.png)

### ISO 15765-2 Frame Exchange

**Multi-Frame Transfer Example (7524 bytes):**

```
ESP32                                    STM32
  │                                        │
  │  [10 1D 64 ...] First Frame           │
  │─────────────────────────────────────>│
  │                                        │
  │           [30 08 0A] Flow Control      │
  │<─────────────────────────────────────│
  │           (BS=8, STmin=10ms)           │
  │                                        │
  │  [21 ...] Consecutive Frame (seq=1)   │
  │─────────────────────────────────────>│
  │          (wait 10ms)                   │
  │  [22 ...] CF (seq=2)                  │
  │─────────────────────────────────────>│
  │          ...                           │
  │  [28 ...] CF (seq=8)                  │
  │─────────────────────────────────────>│
  │                                        │
  │           [30 08 0A] Flow Control      │
  │<─────────────────────────────────────│
  │                                        │
  │  [29 ...] CF (seq=9)                  │
  │─────────────────────────────────────>│
  │          ...                           │
  │  [2F 0F ...] CF (seq=15, last)        │
  │─────────────────────────────────────>│
  │                                        │
```

**Performance:**
- Block Size (BS): 8 frames/block
- Separation Time (STmin): 10ms (mandatory delay between frames)
- Throughput: 583 bytes/sec
- Total Transfer Time (7524 bytes): ~16 seconds

---

## 🔒 Security Mechanisms

### Dual ECDSA Signature Architecture

**Why Two Signatures?**

| Signature | When Created | When Verified | Purpose |
|-----------|-------------|---------------|---------|
| **Encrypted Firmware Signature** | Python (after AES encryption) | ESP32 + STM32 (OTA phase) | Authenticate OTA transport |
| **Plaintext Firmware Signature** | Python (before AES encryption) | STM32 (every boot) | Secure boot enforcement |

**Attack Scenarios Prevented:**

1. **Network MITM Attack:**
   - Attacker modifies encrypted firmware during download
   - ESP32 detects SHA-256 mismatch → Rejects before CAN
   - STM32 verifies ECDSA signature → Rejects if tampered

2. **Flash Tampering (Post-OTA):**
   - Attacker uses debugger to modify plaintext firmware in Slot A
   - Next boot: STM32 verifies plaintext_signature → Infinite loop
   - **Result:** Unauthorized firmware cannot execute

3. **Replay Attack:**
   - Attacker re-sends old firmware version
   - Version check fails (optional feature, can be implemented)

### Cryptographic Algorithms

**AES-128-CBC Encryption:**
- **Mode:** CBC (Cipher Block Chaining)
- **Key Size:** 128 bits (16 bytes)
- **IV:** Randomly generated per firmware (16 bytes)
- **Padding:** PKCS7 (1-16 bytes)
- **Performance:** 4.6 KB/s decryption on STM32 @ 72MHz

**ECDSA P-256 Digital Signature:**
- **Curve:** secp256r1 (NIST P-256)
- **Signature Format:** Raw r||s (64 bytes, no DER encoding)
- **Performance:** 611ms verification on STM32 @ 72MHz

**SHA-256 Hashing:**
- **Output Size:** 256 bits (32 bytes)
- **Performance:** 350 KB/s on STM32 @ 72MHz
- **Use Cases:** Transport integrity, decryption correctness, boot-time validation

---

## 🛠️ Repository Structure

```
SECURE_FOTA_UDS_CAN_BUS/
├── README.md                           # ⭐ This file
├── DIAGRAM_GUIDE.txt                   # ⭐ Technical documentation
├── .gitignore                          # ⭐ Whitelist security strategy
│
├── Diagrams/                           # ⭐ System diagrams
│   ├── SYSTEM ARCHITECTURE.drawio.png
│   ├── OTA FLOW.drawio.png
│   ├── MEMORY MAP LAYOUT STM32.drawio.png
│   └── CAN-TP SEQUENCE DIAGRAM.drawio.png
│
├── SERVER_PYTHON/                      # Python FOTA Manager
│   ├── crypto_utils.py                 # ⭐ AES, ECDSA, SHA-256 implementation
│   ├── firmware_manager.py             # ⭐ 228-byte header packaging
│   ├── protocol.py                     # ⭐ FOTA protocol definitions
│   ├── network_utils.py                # ⭐ TCP/UDP networking
│   ├── requirements.txt                # ⭐ Python dependencies
│   ├── main.py                         # 🔒 GUI application (PRIVATE)
│   ├── firebase_config.json            # 🔒 CRITICAL: Firebase credentials
│   └── README.md                       # ⭐ Python component documentation
│
├── Gateway_FOTA_ESP32/                 # ESP32 Gateway
│   ├── main/
│   │   ├── src/
│   │   │   ├── uds_client.cpp          # ⭐ UDS protocol implementation
│   │   │   ├── isotp_client.cpp        # ⭐ CAN-TP transport layer
│   │   │   ├── udp_discovery.cpp       # ⭐ Device discovery
│   │   │   ├── fota_security.cpp       # ⭐ Pre-validation firewall
│   │   │   └── version_checker.cpp     # ⭐ Metadata comparison
│   │   ├── include/                    # ⭐ Header files
│   │   └── main.cpp                    # 🔒 Application entry (PRIVATE)
│   ├── CMakeLists.txt                  # ⭐ ESP-IDF build config
│   └── README.md                       # ⭐ ESP32 component documentation
│
├── Target_ECU_STM32_Bootloader/        # STM32 Secure Bootloader
│   ├── Core/
│   │   ├── Src/
│   │   │   ├── dual_slot_manager.c     # ⭐ Dual-bank flash management
│   │   │   ├── aes_decrypt.c           # ⭐ Stream-based AES decryption
│   │   │   ├── fota_security.c         # ⭐ Verify-then-decrypt pipeline
│   │   │   ├── cantp.c                 # ⭐ CAN-TP server
│   │   │   ├── uds_server.c            # ⭐ UDS server
│   │   │   ├── flash_ops.c             # ⭐ Flash programming
│   │   │   └── power_loss_recovery.c   # ⭐ Checkpoint recovery
│   │   ├── Inc/                        # ⭐ Header files
│   │   └── main.c                      # 🔒 Bootloader entry (PRIVATE)
│   └── README.md                       # ⭐ Bootloader documentation
│
└── Target_ECU_STM32_Application/       # STM32 User Application
    ├── Core/
    │   ├── Src/
    │   │   ├── firmware_header.c       # ⭐ Metadata self-reading
    │   │   ├── can.c                   # ⭐ CAN communication
    │   │   └── version.c               # ⭐ Version reporting
    │   ├── Inc/                        # ⭐ Header files
    │   └── main.c                      # 🔒 Application entry (PRIVATE)
    └── README.md                       # ⭐ Application documentation
```

**Legend:**  
⭐ = Whitelisted (publicly showcased for portfolio)  
🔒 = Private (protected by .gitignore for security/IP)

---

## 🚀 Quick Start

### 1. Python Server Setup

```bash
cd SERVER_PYTHON
pip install -r requirements.txt
python main.py
# Load firmware → Sign & Package → Select Cloud/LAN mode
```

### 2. ESP32 Gateway Setup

```bash
cd Gateway_FOTA_ESP32
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

### 3. STM32 Bootloader Setup

```bash
cd Target_ECU_STM32_Bootloader
# Open in Keil MDK-ARM
# Build → Flash to 0x08000000
```

### 4. Hardware Connections

**CAN Bus:**
- ESP32 (GPIO21/22) ↔ SN65HVD230 ↔ STM32 (PA11/PA12)
- 120Ω termination resistor between CANH and CANL

**Power:**
- ESP32: 5V USB or 3.3V regulated
- STM32: 3.3V via ST-Link or external regulator

### 5. Run OTA Update

1. Start Python FOTA Manager (LAN mode)
2. ESP32 auto-discovers server via UDP
3. Touch "Update" button on ESP32 LCD
4. Monitor progress: ESP32 LCD + STM32 UART
5. Verify: "APPLICATION START v1.2.1"

---

## 📊 Performance Metrics

### End-to-End OTA Timeline

| Phase | Operation | Duration |
|-------|-----------|----------|
| **ESP32 Download** | HTTPS from Firebase | ~2s |
| **ESP32 Pre-validation** | SHA-256 + ECDSA | ~700ms |
| **CAN-TP Transfer** | UDS 0x36 (8 blocks) | ~16s |
| **STM32 Verification** | 5-stage crypto pipeline | ~2.8s |
| **STM32 Flash Write** | Slot B → A copy | ~3s |
| **Total** | | **~23s** |

**Bottleneck:** CAN-TP STmin=10ms mandatory delay (16s for 7524 bytes)

### Cryptographic Performance (STM32 @ 72MHz)

| Operation | Time | Throughput |
|-----------|------|------------|
| SHA-256 (7284 bytes) | 21ms | 350 KB/s |
| ECDSA Verify | 611ms | - |
| AES-128 Decrypt (7296 bytes) | 1562ms | 4.6 KB/s |

---

## 🧪 Testing

### Hardware Requirements

- **Python Server:** Windows/Linux PC with Wi-Fi/Ethernet
- **ESP32 Gateway:** ESP32-DevKitC + W5500 + SN65HVD230
- **STM32 ECU:** STM32F103C8T6 Blue Pill + ST-Link V2
- **CAN Bus:** 120Ω termination resistor

### Test Scenarios

1. **Successful OTA Update:**  
   Encrypted firmware (7296 bytes) → Verify → Decrypt → Flash → Boot

2. **Corrupted Firmware Detection:**  
   Modify 1 byte → ESP32 SHA-256 mismatch → Reject (NRC 0x72)

3. **Invalid Signature Rejection:**  
   Wrong ECDSA key → STM32 verification fails → Reject (NRC 0x72)

4. **Power-Loss Recovery:**  
   Cut power at 50% copy → Restore → Resume from checkpoint → Complete

5. **NRC 0x78 Keep-Alive:**  
   Long verification (5.2s) → ESP32 receives 3× NRC 0x78 → No timeout

---

## 🐛 Troubleshooting

### Common Issues

**"ECDSA verification failed"**
- Public key mismatch (ESP32/STM32 vs Python)
- Solution: Regenerate keypair, copy to all components

**"AES decryption produces garbage"**
- IV or key mismatch
- Solution: Verify `aes_key.h` consistent across Python/STM32

**"Application doesn't start after OTA"**
- Vector table offset wrong (`VECT_TAB_OFFSET != 0x7C00`)
- Solution: Check `system_stm32f1xx.c` in application

**"UDS timeout during 0x37"**
- NRC 0x78 not handled
- Solution: Verify ESP32 retry logic (max 10 retries)

---

## 📚 Documentation

- **[DIAGRAM_GUIDE.txt](DIAGRAM_GUIDE.txt):** Detailed technical specifications for all 5 diagrams
- **[SERVER_PYTHON/README.md](SERVER_PYTHON/README.md):** Python FOTA Manager documentation
- **[Gateway_FOTA_ESP32/README.md](Gateway_FOTA_ESP32/README.md):** ESP32 Gateway documentation
- **[Target_ECU_STM32_Bootloader/README.md](Target_ECU_STM32_Bootloader/README.md):** STM32 Bootloader documentation
- **[Target_ECU_STM32_Application/README.md](Target_ECU_STM32_Application/README.md):** STM32 Application documentation

---

## 🎓 Key Technical Achievements

### Automotive Standards Compliance
- **ISO 14229-1:** UDS diagnostic services (0x10, 0x22, 0x34, 0x36, 0x37)
- **ISO 15765-2:** CAN-TP transport layer (FF, CF, FC frames)
- **ISO 11898:** CAN physical layer (125 kbps, 11-bit identifiers)

### Cryptographic Implementation
- **ECDSA P-256:** secp256r1 curve, raw r||s format (no DER)
- **AES-128-CBC:** Stream-based decryption (256-byte chunks, RAM-efficient)
- **SHA-256:** Double-hashing (plaintext + encrypted firmware)

### Embedded Systems Engineering
- **Memory-Constrained Design:** 20KB RAM, stream-based crypto (no full-buffer copy)
- **Dual-Slot Flash Management:** Atomic B→A copy with power-loss recovery
- **Secure Boot:** Mandatory ECDSA verification, vector table validation
- **Real-Time Protocol:** NRC 0x78 keep-alive prevents timeout during 5.2s verification

### Network Architecture
- **Multi-Interface Gateway:** Wi-Fi (HTTPS), Ethernet (TCP), CAN Bus
- **Protocol Translation:** HTTP/TCP → UDS/CAN-TP bridge
- **Security Firewall:** Pre-validation before CAN transmission
- **Device Discovery:** UDP broadcast auto-detection protocol

---

## 📄 License

**Academic Project** - For educational and portfolio demonstration purposes.

**Security Notice:** This implementation uses industry-standard cryptographic algorithms but is intended for academic study. For production automotive systems, consult with certified security auditors and comply with **ISO/SAE 21434** (Cybersecurity Engineering).

---

## 👤 Author

**Embedded Systems Engineer**  
**Specialization:** Automotive Security, Cryptographic Protocols, OTA Updates, UDS/CAN-TP

**Skills Demonstrated:**
- Multi-layer system architecture (Python, ESP32, STM32)
- Automotive diagnostic protocols (ISO 14229-1, ISO 15765-2)
- Embedded cryptography (ECDSA, AES, SHA-256)
- Real-time embedded systems (FreeRTOS, bare-metal STM32)
- Network security (TLS/SSL, pre-validation firewalls)
- Fail-safe design (dual-slot flash, power-loss recovery)

**Contact:** [Your Email] | [GitHub] | [LinkedIn]

---

## 🙏 Acknowledgments

- **Automotive Standards:** ISO 14229-1 (UDS), ISO 15765-2 (CAN-TP), ISO 11898 (CAN Physical)
- **Cryptographic Libraries:**
  - Python: `cryptography` (OpenSSL backend)
  - ESP32: `mbedtls` (ECDSA verification)
  - STM32: `micro-ecc`, `tiny-AES-c`, `sha256_minimal`
- **Frameworks:**
  - ESP-IDF v5.3.4 (Espressif Systems)
  - STM32 HAL (STMicroelectronics)
  - Firebase Admin SDK (Google)
  - LVGL v8.3 (GUI framework)
- **Tools:**
  - Keil MDK-ARM v5.37
  - STM32CubeMX v6.10
  - Visual Studio Code + ESP-IDF extension
  - Draw.io (system diagrams)

---

**⭐ If this project helped you learn about automotive security or embedded OTA systems, please consider starring the repository!**
