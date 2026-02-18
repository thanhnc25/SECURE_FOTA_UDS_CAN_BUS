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
Cloud Mode:  Upload to Firebase storage → ESP32 HTTPS download
LAN Mode:    TCP server + UDP beacon
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

---

## 📡 CAN-TP Sequence Diagram

![CAN-TP Sequence](Diagrams/CAN-TP%20SEQUENCE%20DIAGRAM.drawio.png)

### ISO 15765-2 Frame Exchange

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
