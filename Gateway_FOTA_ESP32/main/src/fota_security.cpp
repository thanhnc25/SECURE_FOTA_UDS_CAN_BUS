#include "fota/fota_security.hpp"

#include <cstring>

#include "esp_log.h"

#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"

#include "public_key.h"
#include "esp_err.h"

namespace fota
{
static const char* const TAG = "FOTA_SEC";


static esp_err_t compute_sha256_full(const uint8_t* data, size_t len, uint8_t out_hash[32])
{
    if (data == nullptr || out_hash == nullptr || len == 0U)
    {
        return ESP_ERR_INVALID_ARG;
    }

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

    int rc = mbedtls_sha256_starts(&ctx, 0 /* is224 */);
    if (rc != 0)
    {
        mbedtls_sha256_free(&ctx);
        return ESP_FAIL;
    }

    rc = mbedtls_sha256_update(&ctx, data, len);
    if (rc != 0)
    {
        mbedtls_sha256_free(&ctx);
        return ESP_FAIL;
    }

    rc = mbedtls_sha256_finish(&ctx, out_hash);
    mbedtls_sha256_free(&ctx);

    return (rc == 0) ? ESP_OK : ESP_FAIL;
}

static void hex_dump(const char* label, const uint8_t* data, size_t len)
{
    if (data == nullptr || len == 0U)
    {
        return;
    }
    ESP_LOGI(TAG, "%s (%u bytes):", label, (unsigned)len);
    for (size_t i = 0; i < len; i += 16)
    {
        char buf[64];
        int off = 0;
        for (size_t j = 0; j < 16 && (i + j) < len; ++j)
        {
            off += snprintf(buf + off, sizeof(buf) - off, "%02X ", data[i + j]);
        }
        ESP_LOGI(TAG, "  %s", buf);
    }
}

#ifndef FOTA_ECDSA_CURVE
// Using SECP256R1 (NIST P-256) - standard curve for embedded systems
#define FOTA_ECDSA_CURVE MBEDTLS_ECP_DP_SECP256R1
#endif

static bool is_all_zero(const uint8_t* p, size_t len)
{
    if (p == nullptr)
    {
        return true;
    }
    for (size_t i = 0; i < len; ++i)
    {
        if (p[i] != 0)
        {
            return false;
        }
    }
    return true;
}


esp_err_t verify_ecdsa_rs_raw(const uint8_t hash[32], const uint8_t sig_rs[64])
{
    if (hash == nullptr || sig_rs == nullptr)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (is_all_zero(sig_rs, 64))
    {
        ESP_LOGE(TAG, "ECDSA signature is all-zero");
        return ESP_ERR_INVALID_RESPONSE;
    }

    ESP_LOGI(TAG, "ECDSA verify: curve=SECP256R1 (NIST P-256)");
    hex_dump("Hash", hash, 32);
    hex_dump("Signature (r||s)", sig_rs, 64);
    hex_dump("Public key X", ECU_PUBLIC_KEY, 32);
    hex_dump("Public key Y", ECU_PUBLIC_KEY + 32, 32);

    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi r;
    mbedtls_mpi s;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    int rc = mbedtls_ecp_group_load(&grp, (mbedtls_ecp_group_id)FOTA_ECDSA_CURVE);
    if (rc != 0)
    {
        ESP_LOGE(TAG, "ecp_group_load rc=%d", rc);
        goto cleanup_fail;
    }

    // Load public key Q = (X, Y)
    rc = mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(X), ECU_PUBLIC_KEY, 32);
    if (rc != 0)
    {
        ESP_LOGE(TAG, "read X rc=%d", rc);
        goto cleanup_fail;
    }
    rc = mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(Y), ECU_PUBLIC_KEY + 32, 32);
    if (rc != 0)
    {
        ESP_LOGE(TAG, "read Y rc=%d", rc);
        goto cleanup_fail;
    }
    rc = mbedtls_mpi_lset(&Q.MBEDTLS_PRIVATE(Z), 1);
    if (rc != 0)
    {
        ESP_LOGE(TAG, "set Z rc=%d", rc);
        goto cleanup_fail;
    }

    // Load signature r,s
    rc = mbedtls_mpi_read_binary(&r, sig_rs, 32);
    if (rc != 0)
    {
        ESP_LOGE(TAG, "read r rc=%d", rc);
        goto cleanup_fail;
    }
    rc = mbedtls_mpi_read_binary(&s, sig_rs + 32, 32);
    if (rc != 0)
    {
        ESP_LOGE(TAG, "read s rc=%d", rc);
        goto cleanup_fail;
    }

    rc = mbedtls_ecdsa_verify(&grp, hash, 32, &Q, &r, &s);
    if (rc != 0)
    {
        ESP_LOGE(TAG, "ecdsa_verify failed rc=%d", rc);
        goto cleanup_fail;
    }

    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);
    return ESP_OK;

cleanup_fail:
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);
    return ESP_FAIL;
}

esp_err_t verify_firmware(const Header& header, const uint8_t* firmware, size_t firmware_len, VerifyResult* out)
{
    if (firmware == nullptr || firmware_len == 0 || out == nullptr)
    {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t hash_full[32];
    esp_err_t err_full = compute_sha256_full(firmware, firmware_len, hash_full);
    if (err_full != ESP_OK)
    {
        ESP_LOGE(TAG, "SHA256 compute failed");
        return err_full;
    }

    out->sha256_ok = false;
    out->ecdsa_ok = false;
    if (memcmp(hash_full, header.sha256, 32) == 0) {
        out->sha256_ok = true;
        ESP_LOGI(TAG, "SHA256 OK (full payload)");
    } else {
        ESP_LOGE(TAG, "SHA256 mismatch");
        return ESP_ERR_INVALID_CRC;
    }

    esp_err_t err = verify_ecdsa_rs_raw(hash_full, header.signature);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ECDSA verify failed");
        return ESP_ERR_INVALID_RESPONSE;
    }
    out->ecdsa_ok = true;
    ESP_LOGI(TAG, "ECDSA OK");
    return ESP_OK;
}
} // namespace fota
