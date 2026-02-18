/**
 ******************************************************************************
 * @file    fota_protocol.h
 * @brief   FOTA Protocol Header Structure (164 bytes - with AES IV + Original SHA256)
 * @note    MUST match ESP32 Gateway protocol definition
 * 
 * SECURITY ARCHITECTURE:
 * ======================
 * This header implements a "Verify-then-Decrypt" security pipeline:
 * 
 * 1. Transport Security (Encrypted Container):
 *    - sha256[32]:     Hash of ENCRYPTED firmware
 *    - signature[64]:  ECDSA P-256 signature on encrypted hash
 *    - aes_iv[16]:     AES-128-CBC initialization vector
 *    Purpose: Verify integrity and authenticity BEFORE decryption
 * 
 * 2. Payload Security (Plaintext Firmware):
 *    - original_sha256[32]: Hash of PLAINTEXT firmware (before encryption)
 *    Purpose: Verify decryption was successful and data is intact
 * 
 * This dual-hash approach ensures both encrypted container integrity
 * (prevents tampering during transport) and plaintext integrity
 * (prevents decryption errors or corruption).
 * 
 * PROTOCOL FLOW:
 * ==============
 * Server (Python):
 * 1. Generate plaintext firmware
 * 2. Calculate original_sha256 = SHA-256(plaintext)
 * 3. Encrypt with AES-128-CBC -> encrypted firmware
 * 4. Calculate sha256 = SHA-256(encrypted)
 * 5. Sign: signature = ECDSA-Sign(sha256)
 * 6. Package: header || encrypted firmware
 * 
 * Client (STM32 Bootloader):
 * 1. Receive encrypted package
 * 2. Verify sha256 == SHA-256(encrypted) [Container integrity]
 * 3. Verify ECDSA signature [Authenticity]
 * 4. Decrypt: plaintext = AES-Decrypt(encrypted)
 * 5. Verify original_sha256 == SHA-256(plaintext) [Payload integrity]
 * 6. Execute plaintext firmware
 ******************************************************************************
 */

#ifndef FOTA_PROTOCOL_H
#define FOTA_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol Constants */
#define FOTA_MAGIC              0x41544F46U  /* 'FOTA' */
#define FOTA_HEADER_SIZE        228U         /* Updated: 164→228 bytes (added plaintext_signature) */

/* Security Flags */
/* Security Flags */
/* #define FOTA_FLAG_SHA256        0x0001U */
/* #define FOTA_FLAG_ECDSA         0x0002U */
/* #define FOTA_FLAG_COMPRESSED    0x0004U */

/**
 * @brief FOTA Header Structure (228 bytes)
 * @note Matches Python/ESP32: struct '<4s12sI32s64s16s32s64s' (little-endian)
 * @note Layout:
 *   - magic:          4 bytes ('FOTA')
 *   - version:       12 bytes ASCII
 *   - firmware_size:  4 bytes
 *   - sha256:        32 bytes (SHA-256 of encrypted firmware)
 *   - signature:     64 bytes (ECDSA signature of encrypted: r||s)
 *   - aes_iv:        16 bytes (AES-128-CBC IV)
 *   - original_sha256: 32 bytes (SHA-256 of plaintext firmware)
 *   - plaintext_signature: 64 bytes (ECDSA signature of plaintext: r||s for secure boot)
 */
#if defined(__CC_ARM)
__packed typedef struct
{
    uint32_t magic;         /* 'FOTA' */
    char     version[12];   /* ASCII version */
    uint32_t firmware_size; /* Firmware size in bytes */
    uint8_t sha256[32];     /* SHA-256 hash (encrypted firmware) */
    uint8_t signature[64];  /* ECDSA signature (r||s) of encrypted firmware */
    uint8_t aes_iv[16];     /* AES-128-CBC Initialization Vector */
    uint8_t original_sha256[32]; /* SHA-256 hash (plaintext firmware) */
    uint8_t plaintext_signature[64]; /* ECDSA signature (r||s) of plaintext firmware for secure boot */
} fota_header_t;
#else
typedef struct __attribute__((packed))
{
    uint32_t magic;         /* 'FOTA' */
    char     version[12];   /* ASCII version */
    uint32_t firmware_size; /* Firmware size in bytes */
    uint8_t sha256[32];     /* SHA-256 hash (encrypted firmware) */
    uint8_t signature[64];  /* ECDSA signature (r||s) of encrypted firmware */
    uint8_t aes_iv[16];     /* AES-128-CBC Initialization Vector */
    uint8_t original_sha256[32]; /* SHA-256 hash (plaintext firmware) */
    uint8_t plaintext_signature[64]; /* ECDSA signature (r||s) of plaintext firmware for secure boot */
} fota_header_t;
#endif

/* Compile-time size check (compatible with Keil ARMCC v5) */
#ifdef __GNUC__
_Static_assert(sizeof(fota_header_t) == FOTA_HEADER_SIZE, "FOTA header must be 164 bytes");
#else
/* Keil ARMCC v5 doesn't support _Static_assert, use typedef trick */
typedef char fota_header_size_check[(sizeof(fota_header_t) == FOTA_HEADER_SIZE) ? 1 : -1];
#endif

#ifdef __cplusplus
}
#endif

#endif /* FOTA_PROTOCOL_H */
