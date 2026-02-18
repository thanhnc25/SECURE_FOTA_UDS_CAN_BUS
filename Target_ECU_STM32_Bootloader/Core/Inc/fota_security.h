/**
 ******************************************************************************
 * @file    fota_security.h
 * @brief   FOTA Security Module - ECDSA + SHA256 Verification
 * @note    Uses micro-ecc (SECP256R1) + minimal SHA-256
 * @note    No dynamic memory allocation (suitable for STM32F103)
 ******************************************************************************
 */

#ifndef FOTA_SECURITY_H
#define FOTA_SECURITY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "fota_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Cached ECDSA public key for performance */
typedef struct {
    uint8_t initialized;
    uint8_t public_key[64];  /* X||Y coordinates */
} ecdsa_key_cache_t;

extern ecdsa_key_cache_t g_ecdsa_key_cache;

/**
 * @brief Verification result structure
 */
typedef struct
{
    bool sha256_ok;     /* SHA-256 hash matched */
    bool ecdsa_ok;      /* ECDSA signature verified */
} fota_verify_result_t;

/**
 * @brief Verify firmware signature (SHA-256 + ECDSA)
 * @param header FOTA header (contains hash and signature)
 * @param firmware Firmware data pointer (Slot B)
 * @param firmware_len Firmware length in bytes
 * @param result Output verification result
 * @return 0 on success, -1 on error
 * 
 * @note Process:
 *   1. Calculate SHA-256 of firmware
 *   2. Compare with header.sha256
 *   3. Verify ECDSA signature (header.signature)
 */
int fota_verify_firmware(const fota_header_t* header,
                         const uint8_t* firmware,
                         size_t firmware_len,
                         fota_verify_result_t* result);

/**
 * @brief Compute SHA-256 hash
 * @param data Input data
 * @param len Data length
 * @param hash Output hash (32 bytes)
 * @return 0 on success, -1 on error
 */
int fota_compute_sha256(const uint8_t* data, size_t len, uint8_t hash[32]);

/**
 * @brief Verify ECDSA signature (raw r||s format)
 * @param hash SHA-256 hash (32 bytes)
 * @param signature ECDSA signature (64 bytes: r||s)
 * @return 0 on success, -1 on error
 * 
 * @note Uses ECU_PUBLIC_KEY (64 bytes) embedded in firmware
 */
int fota_verify_ecdsa(const uint8_t hash[32], const uint8_t signature[64]);

/**
 * @brief Verify firmware with encrypted container validation
 * @param header FOTA header (contains encrypted hash, plaintext hash, and signature)
 * @param encrypted_firmware Encrypted firmware data pointer
 * @param encrypted_len Encrypted firmware length
 * @param plaintext_firmware Decrypted firmware data pointer (or NULL if not decrypted yet)
 * @param plaintext_len Plaintext firmware length (or 0 if not decrypted yet)
 * @param result Output verification result
 * @return 0 on success, -1 on error
 * 
 * @note Verify-then-Decrypt flow:
 *   1. Verify SHA-256 of encrypted container (header.sha256)
 *   2. Verify ECDSA signature on encrypted hash
 *   3. If plaintext provided: Verify SHA-256 of decrypted firmware (header.original_sha256)
 * 
 * @note This implements the "validate both encrypted and decrypted" requirement
 */
int fota_verify_encrypted_firmware(const fota_header_t* header,
                                   const uint8_t* encrypted_firmware,
                                   size_t encrypted_len,
                                   const uint8_t* plaintext_firmware,
                                   size_t plaintext_len,
                                   fota_verify_result_t* result);

#ifdef __cplusplus
}
#endif

#endif /* FOTA_SECURITY_H */
