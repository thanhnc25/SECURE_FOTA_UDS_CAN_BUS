/**
 ******************************************************************************
 * @file    fota_security.c
 * @brief   FOTA Security Implementation (SHA-256 + ECDSA verification)
 * @note    Uses micro-ecc library (SECP256R1 only)
 ******************************************************************************
 */

#include "fota_security.h"
#include "sha256_minimal.h"
#include "uECC_config.h"  /* MUST include BEFORE uECC.h */
#include "uECC.h"
#include "public_key.h"
#include <string.h>

/* Global ECDSA key cache (initialized once to save time) */
ecdsa_key_cache_t g_ecdsa_key_cache = {0};

/* Initialize ECDSA key cache on first use */
static void init_ecdsa_key_cache(void)
{
    if (g_ecdsa_key_cache.initialized == 0)
    {
        memcpy(g_ecdsa_key_cache.public_key, ECU_PUBLIC_KEY, 64);
        g_ecdsa_key_cache.initialized = 1;
    }
}

/* Check if all bytes are zero */
static bool is_all_zero(const uint8_t* data, size_t len)
{
    if (data == NULL)
    {
        return true;
    }
    
    for (size_t i = 0; i < len; i++)
    {
        if (data[i] != 0)
        {
            return false;
        }
    }
    return true;
}

/* Chunked SHA-256 computation (256-byte chunks to save RAM) */
int fota_compute_sha256(const uint8_t* data, size_t len, uint8_t hash[32])
{
    if (data == NULL || hash == NULL || len == 0)
    {
        return -1;
    }

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    
    /* Process in 256-byte chunks to minimize RAM usage */
    const size_t CHUNK_SIZE = 256;
    size_t offset = 0;
    
    while (offset < len)
    {
        size_t chunk_len = (len - offset < CHUNK_SIZE) ? (len - offset) : CHUNK_SIZE;
        sha256_update(&ctx, data + offset, chunk_len);
        offset += chunk_len;
    }
    
    sha256_final(&ctx, hash);
    return 0;
}

int fota_verify_ecdsa(const uint8_t hash[32], const uint8_t signature[64])
{
    if (hash == NULL || signature == NULL)
    {
        return -1;
    }

    /* Check if signature is all zeros (invalid) */
    if (is_all_zero(signature, 64))
    {
        return -1;
    }

    /* Initialize cached key on first use */
    init_ecdsa_key_cache();

    /* micro-ecc expects signature as r||s (64 bytes) */
    /* Use cached public key (X||Y) to avoid re-parsing */
    
    const struct uECC_Curve_t* curve = uECC_secp256r1();
    
    /* Verify using cached public key */
    int result = uECC_verify(g_ecdsa_key_cache.public_key, hash, 32, signature, curve);
    
    return (result == 1) ? 0 : -1;  /* 1 = success, 0 = failure */
}

int fota_verify_firmware(const fota_header_t* header,
                         const uint8_t* firmware,
                         size_t firmware_len,
                         fota_verify_result_t* result)
{
    if (header == NULL || firmware == NULL || firmware_len == 0 || result == NULL)
    {
        return -1;
    }

    /* Initialize result */
    result->sha256_ok = false;
    result->ecdsa_ok = false;

    /* Check header magic */
    if (header->magic != FOTA_MAGIC)
    {
        return -1;  /* Invalid header */
    }

    /* Compute SHA-256 hash of firmware */
    uint8_t computed_hash[32];
    if (fota_compute_sha256(firmware, firmware_len, computed_hash) != 0)
    {
        return -1;
    }

    /* Verify SHA-256 hash */
    if (memcmp(computed_hash, header->sha256, 32) == 0)
    {
        result->sha256_ok = true;
    }
    else
    {
        return -1;  /* Hash mismatch */
    }

    /* Verify ECDSA signature */
    if (fota_verify_ecdsa(computed_hash, header->signature) == 0)
    {
        result->ecdsa_ok = true;
    }
    else
    {
        return -1;  /* Signature verification failed */
    }

    return 0;  /* Both checks passed */
}

int fota_verify_encrypted_firmware(const fota_header_t* header,
                                   const uint8_t* encrypted_firmware,
                                   size_t encrypted_len,
                                   const uint8_t* plaintext_firmware,
                                   size_t plaintext_len,
                                   fota_verify_result_t* result)
{
    if (header == NULL || encrypted_firmware == NULL || encrypted_len == 0 || result == NULL)
    {
        return -1;
    }

    /* Initialize result */
    result->sha256_ok = false;
    result->ecdsa_ok = false;

    /* Check header magic */
    if (header->magic != FOTA_MAGIC)
    {
        return -1;
    }

    /* Step 1: Verify SHA-256 of encrypted container (header.sha256) */
    uint8_t encrypted_hash[32];
    if (fota_compute_sha256(encrypted_firmware, encrypted_len, encrypted_hash) != 0)
    {
        return -1;
    }

    if (memcmp(encrypted_hash, header->sha256, 32) != 0)
    {
        /* Encrypted container hash mismatch */
        return -1;
    }

    /* Step 2: Verify ECDSA signature on encrypted hash */
    if (fota_verify_ecdsa(encrypted_hash, header->signature) != 0)
    {
        /* Signature verification failed */
        return -1;
    }

    result->ecdsa_ok = true;

    /* Step 3: If plaintext provided, verify original_sha256 */
    if (plaintext_firmware != NULL && plaintext_len > 0)
    {
        /* Check if original_sha256 is non-zero (indicates encrypted firmware) */
        bool has_original_hash = false;
        for (size_t i = 0; i < 32; i++)
        {
            if (header->original_sha256[i] != 0)
            {
                has_original_hash = true;
                break;
            }
        }

        if (has_original_hash)
        {
            uint8_t plaintext_hash[32];
            if (fota_compute_sha256(plaintext_firmware, plaintext_len, plaintext_hash) != 0)
            {
                return -1;
            }

            if (memcmp(plaintext_hash, header->original_sha256, 32) != 0)
            {
                /* Plaintext hash mismatch */
                return -1;
            }
        }
    }

    result->sha256_ok = true;
    return 0;
}
