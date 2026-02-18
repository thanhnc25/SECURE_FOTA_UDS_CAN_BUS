#include "fota/version_checker.hpp"

#include <cstring>
#include <vector>
#include <algorithm>

#include "esp_log.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "cJSON.h"

#include "mbedtls/sha256.h"

#include "fota/fota_protocol.hpp"

#include "can_driver.h"
#include "cantp/cantp.hpp"
#include "fota/uds_client.hpp"

namespace fota
{
static const char* TAG = "VERSION_CHK";

// UDS Service IDs
static constexpr uint8_t UDS_SID_READ_DATA_BY_ID = 0x22U;
static constexpr uint16_t UDS_DID_APP_VERSION = 0xF100U;

static esp_err_t can_send_8(uint32_t id, const uint8_t bytes[8], uint32_t timeout_ms)
{
    can_frame_t frame = {};
    frame.id = id;
    frame.dlc = 8U;
    frame.is_extended = false;
    frame.is_rtr = false;
    memcpy(frame.data, bytes, 8U);
    return can_driver_transmit(&frame, timeout_ms);
}

static esp_err_t isotp_recv(uint32_t rx_id,
                            uint32_t tx_id_for_fc,
                            uint32_t timeout_ms,
                            std::vector<uint8_t>* out_payload)
{
    if (out_payload == nullptr)
    {
        return ESP_ERR_INVALID_ARG;
    }

    out_payload->clear();

    // Wait first frame
    can_frame_t rx = {};
    esp_err_t err = can_driver_receive(&rx, timeout_ms);
    if (err != ESP_OK)
    {
        return err;
    }

    // Filter by rx_id
    while (rx.id != rx_id)
    {
        err = can_driver_receive(&rx, timeout_ms);
        if (err != ESP_OK)
        {
            return err;
        }
    }

    const uint8_t pci_type = static_cast<uint8_t>(rx.data[0] >> 4);

    if (pci_type == 0x0U)
    {
        // Single Frame
        const size_t len = (size_t)(rx.data[0] & 0x0FU);
        if (len > 7U)
        {
            return ESP_FAIL;
        }
        out_payload->assign(&rx.data[1], &rx.data[1 + len]);
        return ESP_OK;
    }

    if (pci_type != 0x1U)
    {
        return ESP_FAIL;
    }

    // First Frame
    size_t total_len = 0U;

    if (rx.data[0] == 0x10U && rx.data[1] == 0x00U)
    {
        // Extended length
        total_len = ((size_t)rx.data[2] << 24) | ((size_t)rx.data[3] << 16) | ((size_t)rx.data[4] << 8) |
                    ((size_t)rx.data[5]);
        out_payload->insert(out_payload->end(), &rx.data[6], &rx.data[8]);
    }
    else
    {
        total_len = (((size_t)(rx.data[0] & 0x0FU)) << 8) | (size_t)rx.data[1];
        out_payload->insert(out_payload->end(), &rx.data[2], &rx.data[8]);
    }

    if (total_len == 0U)
    {
        return ESP_FAIL;
    }

    if (out_payload->size() > total_len)
    {
        out_payload->resize(total_len);
        return ESP_OK;
    }

    // Send Flow Control (CTS)
    uint8_t fc[8] = {0};
    fc[0] = 0x30U; // FC, CTS
    fc[1] = 0x00U; // BS=0 (no further FC)
    fc[2] = 0x00U; // STmin=0
    (void)can_send_8(tx_id_for_fc, fc, 50U);

    // Receive Consecutive Frames
    uint8_t expected_sn = 1U;
    while (out_payload->size() < total_len)
    {
        can_frame_t cf = {};
        err = can_driver_receive(&cf, timeout_ms);
        if (err != ESP_OK)
        {
            return err;
        }
        if (cf.id != rx_id)
        {
            continue;
        }

        const uint8_t t = static_cast<uint8_t>(cf.data[0] >> 4);
        if (t != 0x2U)
        {
            continue;
        }

        const uint8_t sn = static_cast<uint8_t>(cf.data[0] & 0x0FU);
        if (sn != (expected_sn & 0x0FU))
        {
            ESP_LOGW(TAG, "ISO-TP SN mismatch: got=%u expected=%u", (unsigned)sn, (unsigned)(expected_sn & 0x0FU));
            return ESP_FAIL;
        }

        expected_sn++;
        const size_t remaining = total_len - out_payload->size();
        const size_t chunk = std::min<size_t>(7U, remaining);
        out_payload->insert(out_payload->end(), &cf.data[1], &cf.data[1 + chunk]);
    }

    return ESP_OK;
}

static bool hex_to_bytes(const char* hex, std::vector<uint8_t>* out)
{
    if (hex == nullptr || out == nullptr)
    {
        return false;
    }

    size_t len = strlen(hex);
    if ((len % 2) != 0)
    {
        return false;
    }

    out->clear();
    out->reserve(len / 2);

    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    for (size_t i = 0; i < len; i += 2)
    {
        int hi = hex_val(hex[i]);
        int lo = hex_val(hex[i + 1]);
        if (hi < 0 || lo < 0)
        {
            return false;
        }
        out->push_back(static_cast<uint8_t>((hi << 4) | lo));
    }

    return true;
}

static bool der_to_raw_ecdsa_rs(const uint8_t* der, size_t der_len, uint8_t out_rs[64])
{
    if (der == nullptr || out_rs == nullptr || der_len < 8)
    {
        return false;
    }

    size_t idx = 0;
    if (der[idx++] != 0x30)
    {
        return false;
    }

    if (idx >= der_len)
    {
        return false;
    }

    size_t seq_len = 0;
    uint8_t len_byte = der[idx++];
    if (len_byte < 0x80)
    {
        seq_len = len_byte;
    }
    else
    {
        uint8_t len_len = len_byte & 0x7F;
        if (len_len == 0 || len_len > 2 || (idx + len_len) > der_len)
        {
            return false;
        }
        seq_len = 0;
        for (uint8_t i = 0; i < len_len; ++i)
        {
            seq_len = (seq_len << 8) | der[idx++];
        }
    }

    if ((idx + seq_len) > der_len)
    {
        return false;
    }

    auto read_int = [&](uint8_t out[32]) -> bool {
        if (idx >= der_len || der[idx++] != 0x02)
        {
            return false;
        }
        if (idx >= der_len)
        {
            return false;
        }
        size_t int_len = der[idx++];
        if ((idx + int_len) > der_len)
        {
            return false;
        }

        const uint8_t* p = &der[idx];
        size_t p_len = int_len;
        idx += int_len;

        if (p_len > 32)
        {
            if (p_len == 33 && p[0] == 0x00)
            {
                p++;
                p_len = 32;
            }
            else
            {
                return false;
            }
        }

        memset(out, 0, 32);
        memcpy(out + (32 - p_len), p, p_len);
        return true;
    };

    uint8_t r[32];
    uint8_t s[32];
    if (!read_int(r) || !read_int(s))
    {
        return false;
    }

    memcpy(out_rs, r, 32);
    memcpy(out_rs + 32, s, 32);
    return true;
}

static std::string get_base_url(const char* url)
{
    if (url == nullptr)
    {
        return std::string();
    }

    std::string s(url);
    size_t pos = s.find_last_of('/');
    if (pos == std::string::npos)
    {
        return s;
    }
    return s.substr(0, pos + 1);
}

static std::string make_absolute_url(const std::string& base_url, const std::string& maybe_relative)
{
    if (maybe_relative.find("http://") == 0 || maybe_relative.find("https://") == 0)
    {
        return maybe_relative;
    }

    if (base_url.empty())
    {
        return maybe_relative;
    }

    return base_url + maybe_relative;
}

static void copy_version_str(char out[12], const char* version_str)
{
    memset(out, 0, 12);
    if (version_str == nullptr)
    {
        return;
    }

    size_t len = strlen(version_str);
    if (len > 11U)
    {
        len = 11U;
    }
    memcpy(out, version_str, len);
}

static esp_err_t http_get_to_string(const char* url, std::string* out)
{
    if (url == nullptr || out == nullptr)
    {
        return ESP_ERR_INVALID_ARG;
    }

    out->clear();

    auto http_event_handler = [](esp_http_client_event_t *evt) -> esp_err_t {
        std::string* buffer = static_cast<std::string*>(evt->user_data);
        switch (evt->event_id) {
            case HTTP_EVENT_ON_DATA:
                if (!esp_http_client_is_chunked_response(evt->client)) {
                    buffer->append(static_cast<char*>(evt->data), evt->data_len);
                }
                break;
            default:
                break;
        }
        return ESP_OK;
    };

    esp_http_client_config_t config = {};
    config.url = url;
    config.method = HTTP_METHOD_GET;
    config.timeout_ms = 20000;
    config.crt_bundle_attach = esp_crt_bundle_attach;
    config.skip_cert_common_name_check = false;
    config.event_handler = http_event_handler;
    config.user_data = out;

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == nullptr)
    {
        ESP_LOGE(TAG, "Failed to init HTTP client");
        return ESP_FAIL;
    }

    esp_err_t err = esp_http_client_perform(client);
    int status_code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "HTTP GET failed: %s", esp_err_to_name(err));
        return err;
    }

    if (status_code != 200)
    {
        ESP_LOGE(TAG, "HTTP status: %d", status_code);
        return ESP_FAIL;
    }

    if (out->empty())
    {
        ESP_LOGE(TAG, "Empty response");
        return ESP_FAIL;
    }

    return ESP_OK;
}

/**
 * @brief Helper: Send ISO-TP message and receive response
 */
static esp_err_t isotp_send_receive(uint32_t tx_id, uint32_t rx_id, 
                                     const uint8_t* req, size_t req_len,
                                     std::vector<uint8_t>* resp_out,
                                     uint32_t timeout_ms)
{
    ESP_LOGI(TAG, "Sending UDS request: tx=0x%03X rx=0x%03X len=%u", 
             (unsigned)tx_id, (unsigned)rx_id, (unsigned)req_len);
    
    // Send request
    cantp::Config cfg;
    cfg.tx_id = tx_id;
    cfg.rx_fc_id = rx_id;
    cfg.tx_timeout_ms = 50;
    cfg.wait_fc_timeout_ms = 3000;
    cfg.accept_fc_from_any_id = false;
    cfg.log_rx_while_waiting = false;

    esp_err_t err = cantp::send_isotp(req, req_len, cfg);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "ISO-TP send failed: %s", esp_err_to_name(err));
        return err;
    }
    
    ESP_LOGI(TAG, "UDS request sent, waiting for response...");

    // Receive response (ISO-TP)
    err = isotp_recv(rx_id, tx_id, timeout_ms, resp_out);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "ISO-TP recv timeout");
        return err;
    }

    // Debug: print response bytes
    if (!resp_out->empty())
    {
        ESP_LOGI(TAG, "Response data (%u bytes):", (unsigned)resp_out->size());
        for (size_t i = 0; i < resp_out->size(); i++)
        {
            ESP_LOGI(TAG, "  [%u] = 0x%02X", (unsigned)i, (*resp_out)[i]);
        }
    }

    return ESP_OK;
}

esp_err_t get_local_version(std::string* version_out)
{
    if (version_out == nullptr)
    {
        return ESP_ERR_INVALID_ARG;
    }

    version_out->clear();

    // Build UDS request: 0x22 0xF1 0x00
    uint8_t req[3];
    req[0] = UDS_SID_READ_DATA_BY_ID;
    req[1] = (uint8_t)(UDS_DID_APP_VERSION >> 8);
    req[2] = (uint8_t)(UDS_DID_APP_VERSION & 0xFFU);

    std::vector<uint8_t> resp;
    esp_err_t err = isotp_send_receive(0x7E0, 0x7E8, req, sizeof(req), &resp, 3000);
    
    if (err != ESP_OK || resp.empty())
    {
        ESP_LOGE(TAG, "Failed to read local version");
        return ESP_FAIL;
    }

    // Check positive response: 0x62 0xF1 0x00 [version_string]
    if (resp.size() < 3 || resp[0] != 0x62 || resp[1] != 0xF1 || resp[2] != 0x00)
    {
        ESP_LOGE(TAG, "Invalid version response (size=%d)", resp.size());
        if (resp.size() > 0) {
            ESP_LOGE(TAG, "Response bytes: %02X %02X %02X", 
                     resp.size() > 0 ? resp[0] : 0,
                     resp.size() > 1 ? resp[1] : 0,
                     resp.size() > 2 ? resp[2] : 0);
        }
        return ESP_FAIL;
    }

    // Extract version string (may be empty if resp.size() == 3)
    for (size_t i = 3; i < resp.size(); i++)
    {
        version_out->push_back((char)resp[i]);
    }

    // If version is empty, use default
    if (version_out->empty()) {
        *version_out = "1.0.0";
        ESP_LOGW(TAG, "Empty version from ECU, using default: 1.0.0");
    } else {
        ESP_LOGI(TAG, "Local version: %s", version_out->c_str());
    }
    return ESP_OK;
}

esp_err_t get_remote_version(const char* url,
                             std::string* version_out,
                             std::string* firmware_url_out,
                             std::string* metadata_url_out)
{
    if (url == nullptr || version_out == nullptr || firmware_url_out == nullptr || metadata_url_out == nullptr)
    {
        return ESP_ERR_INVALID_ARG;
    }

    version_out->clear();
    firmware_url_out->clear();
    metadata_url_out->clear();

    ESP_LOGI(TAG, "Fetching remote version from: %s", url);

    std::string response_buffer;
    esp_err_t err = http_get_to_string(url, &response_buffer);
    if (err != ESP_OK)
    {
        return err;
    }

    ESP_LOGI(TAG, "Received JSON: %s", response_buffer.c_str());

    // Parse JSON
    cJSON* root = cJSON_Parse(response_buffer.c_str());
    if (root == nullptr)
    {
        ESP_LOGE(TAG, "JSON parse failed");
        return ESP_FAIL;
    }

    cJSON* latest_version = cJSON_GetObjectItem(root, "latest_version");
    cJSON* latest_simple = cJSON_GetObjectItem(root, "latest");
    cJSON* binary_url = cJSON_GetObjectItem(root, "binary_url");
    cJSON* firmware_url = cJSON_GetObjectItem(root, "firmware");
    cJSON* metadata_url = cJSON_GetObjectItem(root, "metadata_url");
    cJSON* metadata_simple = cJSON_GetObjectItem(root, "metadata");

    const char* latest_str = nullptr;
    if (latest_version != nullptr && cJSON_IsString(latest_version))
    {
        latest_str = latest_version->valuestring;
    }
    else if (latest_simple != nullptr && cJSON_IsString(latest_simple))
    {
        latest_str = latest_simple->valuestring;
    }

    const char* firmware_str = nullptr;
    if (binary_url != nullptr && cJSON_IsString(binary_url))
    {
        firmware_str = binary_url->valuestring;
    }
    else if (firmware_url != nullptr && cJSON_IsString(firmware_url))
    {
        firmware_str = firmware_url->valuestring;
    }

    const char* metadata_str = nullptr;
    if (metadata_url != nullptr && cJSON_IsString(metadata_url))
    {
        metadata_str = metadata_url->valuestring;
    }
    else if (metadata_simple != nullptr && cJSON_IsString(metadata_simple))
    {
        metadata_str = metadata_simple->valuestring;
    }

    // Fallback: new schema { latest: "x.y.z", versions: [ { version, firmware, metadata } ] }
    if ((latest_str == nullptr || firmware_str == nullptr) && cJSON_IsString(latest_simple))
    {
        cJSON* versions = cJSON_GetObjectItem(root, "versions");
        if (versions != nullptr && cJSON_IsArray(versions))
        {
            const int count = cJSON_GetArraySize(versions);
            for (int i = 0; i < count; ++i)
            {
                cJSON* item = cJSON_GetArrayItem(versions, i);
                if (item == nullptr)
                {
                    continue;
                }
                cJSON* v = cJSON_GetObjectItem(item, "version");
                if (v == nullptr || !cJSON_IsString(v))
                {
                    continue;
                }
                if (strcmp(v->valuestring, latest_simple->valuestring) != 0)
                {
                    continue;
                }

                latest_str = v->valuestring;

                cJSON* fw = cJSON_GetObjectItem(item, "firmware");
                if (fw != nullptr && cJSON_IsString(fw))
                {
                    firmware_str = fw->valuestring;
                }
                cJSON* md = cJSON_GetObjectItem(item, "metadata");
                if (md != nullptr && cJSON_IsString(md))
                {
                    metadata_str = md->valuestring;
                }
                break;
            }
        }
    }

    if (latest_str == nullptr || firmware_str == nullptr)
    {
        ESP_LOGE(TAG, "Missing JSON fields");
        cJSON_Delete(root);
        return ESP_FAIL;
    }

    *version_out = latest_str;

    // Build full URLs
    const std::string base_url = get_base_url(url);
    *firmware_url_out = make_absolute_url(base_url, std::string(firmware_str));

    if (metadata_str != nullptr)
    {
        *metadata_url_out = make_absolute_url(base_url, std::string(metadata_str));
    }
    else
    {
        *metadata_url_out = std::string();
    }

    ESP_LOGI(TAG, "Remote version: %s", version_out->c_str());
    ESP_LOGI(TAG, "Firmware URL: %s", firmware_url_out->c_str());
    if (!metadata_url_out->empty())
    {
        ESP_LOGI(TAG, "Metadata URL: %s", metadata_url_out->c_str());
    }

    cJSON_Delete(root);
    return ESP_OK;
}

esp_err_t get_header_from_metadata(const char* metadata_url,
                                   size_t firmware_size,
                                   Header* header_out,
                                   std::string* firmware_url_out)
{
    if (metadata_url == nullptr || header_out == nullptr)
    {
        return ESP_ERR_INVALID_ARG;
    }

    std::string meta_json;
    ESP_LOGI(TAG, "Fetching metadata from: %s", metadata_url);
    esp_err_t err = http_get_to_string(metadata_url, &meta_json);
    if (err != ESP_OK)
    {
        return err;
    }

    cJSON* root = cJSON_Parse(meta_json.c_str());
    if (root == nullptr)
    {
        ESP_LOGE(TAG, "Metadata JSON parse failed");
        return ESP_FAIL;
    }

    cJSON* ver_item = cJSON_GetObjectItem(root, "version");
    if (ver_item == nullptr)
    {
        ver_item = cJSON_GetObjectItem(root, "latest_version");
    }

    cJSON* sha_item = cJSON_GetObjectItem(root, "sha256_hash");
    if (sha_item == nullptr)
    {
        sha_item = cJSON_GetObjectItem(root, "sha256");
    }

    cJSON* sig_item = cJSON_GetObjectItem(root, "ecdsa_signature");
    if (sig_item == nullptr)
    {
        sig_item = cJSON_GetObjectItem(root, "signature");
    }

    cJSON* aes_iv_item = cJSON_GetObjectItem(root, "aes_iv");

    cJSON* size_item = cJSON_GetObjectItem(root, "file_size");
    if (size_item == nullptr)
    {
        size_item = cJSON_GetObjectItem(root, "size");
    }

    cJSON* download_url_item = cJSON_GetObjectItem(root, "download_url");

    memset(header_out, 0, sizeof(Header));
    header_out->magic = kMagic;
    header_out->firmware_size = static_cast<uint32_t>(firmware_size);

    if (size_item != nullptr && cJSON_IsNumber(size_item))
    {
        header_out->firmware_size = static_cast<uint32_t>(size_item->valueint);
    }

    if (header_out->firmware_size == 0U && firmware_size > 0U)
    {
        header_out->firmware_size = static_cast<uint32_t>(firmware_size);
    }

    if (ver_item != nullptr && cJSON_IsString(ver_item))
    {
        copy_version_str(header_out->version, ver_item->valuestring);
    }

    if (sha_item != nullptr && cJSON_IsString(sha_item))
    {
        std::vector<uint8_t> sha_bytes;
        if (!hex_to_bytes(sha_item->valuestring, &sha_bytes) || sha_bytes.size() != 32)
        {
            ESP_LOGE(TAG, "Invalid SHA256 in metadata");
            cJSON_Delete(root);
            return ESP_FAIL;
        }
        memcpy(header_out->sha256, sha_bytes.data(), 32);
    }

    if (sig_item != nullptr && cJSON_IsString(sig_item))
    {
        std::vector<uint8_t> sig_bytes;
        if (!hex_to_bytes(sig_item->valuestring, &sig_bytes))
        {
            ESP_LOGE(TAG, "Invalid signature hex in metadata");
            cJSON_Delete(root);
            return ESP_FAIL;
        }

        if (sig_bytes.size() == 64)
        {
            memcpy(header_out->signature, sig_bytes.data(), 64);
        }
        else
        {
            uint8_t rs[64];
            if (!der_to_raw_ecdsa_rs(sig_bytes.data(), sig_bytes.size(), rs))
            {
                ESP_LOGE(TAG, "Unsupported ECDSA signature format");
                cJSON_Delete(root);
                return ESP_FAIL;
            }
            memcpy(header_out->signature, rs, 64);
        }
    }

    // Parse AES IV (16 bytes hex string)
    if (aes_iv_item != nullptr && cJSON_IsString(aes_iv_item))
    {
        std::vector<uint8_t> iv_bytes;
        if (hex_to_bytes(aes_iv_item->valuestring, &iv_bytes) && iv_bytes.size() == 16)
        {
            memcpy(header_out->aes_iv, iv_bytes.data(), 16);
            ESP_LOGI(TAG, "AES IV parsed: %02X%02X%02X%02X...", 
                     header_out->aes_iv[0], header_out->aes_iv[1], 
                     header_out->aes_iv[2], header_out->aes_iv[3]);
        }
        else
        {
            ESP_LOGW(TAG, "Invalid AES IV in metadata, using zeros");
            memset(header_out->aes_iv, 0, 16);
        }
    }
    else
    {
        // No AES IV in metadata (backward compatibility)
        memset(header_out->aes_iv, 0, 16);
        ESP_LOGD(TAG, "No AES IV in metadata");
    }

    // Parse Original SHA256 (32 bytes hex string) - SHA of plaintext firmware
    cJSON* original_sha256_item = cJSON_GetObjectItem(root, "original_sha256");
    if (original_sha256_item != nullptr && cJSON_IsString(original_sha256_item))
    {
        std::vector<uint8_t> original_hash;
        if (hex_to_bytes(original_sha256_item->valuestring, &original_hash) && original_hash.size() == 32)
        {
            memcpy(header_out->original_sha256, original_hash.data(), 32);
            ESP_LOGI(TAG, "Original SHA-256 parsed: %02X%02X%02X%02X...", 
                     header_out->original_sha256[0], header_out->original_sha256[1], 
                     header_out->original_sha256[2], header_out->original_sha256[3]);
        }
        else
        {
            ESP_LOGW(TAG, "Invalid original SHA-256 in metadata, using zeros");
            memset(header_out->original_sha256, 0, 32);
        }
    }
    else
    {
        // No original SHA-256 (backward compatibility or plaintext firmware)
        memset(header_out->original_sha256, 0, 32);
        ESP_LOGD(TAG, "No original SHA-256 in metadata");
    }

    // Parse Plaintext Signature (64 bytes hex string) - ECDSA signature of plaintext firmware for secure boot
    cJSON* plaintext_sig_item = cJSON_GetObjectItem(root, "plaintext_signature");
    if (plaintext_sig_item != nullptr && cJSON_IsString(plaintext_sig_item))
    {
        std::vector<uint8_t> plaintext_sig_bytes;
        if (hex_to_bytes(plaintext_sig_item->valuestring, &plaintext_sig_bytes))
        {
            if (plaintext_sig_bytes.size() == 64)
            {
                memcpy(header_out->plaintext_signature, plaintext_sig_bytes.data(), 64);
                ESP_LOGI(TAG, "Plaintext signature parsed: %02X%02X%02X%02X...", 
                         header_out->plaintext_signature[0], header_out->plaintext_signature[1], 
                         header_out->plaintext_signature[2], header_out->plaintext_signature[3]);
            }
            else
            {
                ESP_LOGW(TAG, "Invalid plaintext signature size (%d bytes), expected 64", plaintext_sig_bytes.size());
                memset(header_out->plaintext_signature, 0, 64);
            }
        }
        else
        {
            ESP_LOGW(TAG, "Invalid plaintext signature hex in metadata");
            memset(header_out->plaintext_signature, 0, 64);
        }
    }
    else
    {
        // No plaintext signature (backward compatibility)
        memset(header_out->plaintext_signature, 0, 64);
        ESP_LOGD(TAG, "No plaintext signature in metadata");
    }

    if (firmware_url_out != nullptr)
    {
        firmware_url_out->clear();
        if (download_url_item != nullptr && cJSON_IsString(download_url_item))
        {
            *firmware_url_out = download_url_item->valuestring;
        }
    }

    cJSON_Delete(root);
    return ESP_OK;
}

int compare_versions(const std::string& version1, const std::string& version2)
{
    // Parse "X.Y.Z" format
    auto parse = [](const std::string& v) -> std::vector<int> {
        std::vector<int> parts;
        std::string temp;
        for (char c : v)
        {
            if (c == '.')
            {
                if (!temp.empty())
                {
                    parts.push_back(std::stoi(temp));
                    temp.clear();
                }
            }
            else if (c >= '0' && c <= '9')
            {
                temp += c;
            }
        }
        if (!temp.empty())
        {
            parts.push_back(std::stoi(temp));
        }
        return parts;
    };

    std::vector<int> v1 = parse(version1);
    std::vector<int> v2 = parse(version2);

    // Pad with zeros
    while (v1.size() < 3) v1.push_back(0);
    while (v2.size() < 3) v2.push_back(0);

    // Compare
    for (size_t i = 0; i < 3; i++)
    {
        if (v1[i] > v2[i]) return 1;
        if (v1[i] < v2[i]) return -1;
    }

    return 0;
}

esp_err_t download_firmware_https(const char* url, uint8_t** out_buffer, size_t* out_size)
{
    if (url == nullptr || out_buffer == nullptr || out_size == nullptr)
    {
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(TAG, "Downloading firmware from: %s", url);

    esp_http_client_config_t config = {};
    config.url = url;
    config.method = HTTP_METHOD_GET;
    config.timeout_ms = 30000;
    config.crt_bundle_attach = esp_crt_bundle_attach;  // Enable certificate bundle verification
    config.skip_cert_common_name_check = false;         // Verify hostname

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == nullptr)
    {
        ESP_LOGE(TAG, "Failed to init HTTP client");
        return ESP_FAIL;
    }

    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "HTTP open failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return err;
    }

    int content_length = esp_http_client_fetch_headers(client);
    if (content_length < 0)
    {
        ESP_LOGE(TAG, "Failed to fetch headers");
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    int status_code = esp_http_client_get_status_code(client);
    if (status_code != 200)
    {
        ESP_LOGE(TAG, "HTTP status: %d", status_code);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Content-Length: %d", content_length);

    std::vector<uint8_t> download_buffer;
    if (content_length > 0)
    {
        download_buffer.reserve((size_t)content_length);
    }
    else
    {
        download_buffer.reserve(64 * 1024);
    }

    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    if (mbedtls_sha256_starts(&sha_ctx, 0) != 0)
    {
        ESP_LOGE(TAG, "SHA256 start failed");
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    uint8_t temp[1024];
    int total_read = 0;
    while (true)
    {
        int read_len = esp_http_client_read(client, (char*)temp, sizeof(temp));
        if (read_len < 0)
        {
            ESP_LOGE(TAG, "HTTP read failed");
            mbedtls_sha256_free(&sha_ctx);
            esp_http_client_close(client);
            esp_http_client_cleanup(client);
            return ESP_FAIL;
        }
        if (read_len == 0)
        {
            break;
        }

        download_buffer.insert(download_buffer.end(), temp, temp + read_len);
        mbedtls_sha256_update(&sha_ctx, temp, read_len);
        total_read += read_len;
    }

    esp_http_client_close(client);
    esp_http_client_cleanup(client);

    if (download_buffer.empty())
    {
        ESP_LOGE(TAG, "No data received");
        mbedtls_sha256_free(&sha_ctx);
        return ESP_FAIL;
    }

    if (content_length > 0 && total_read != content_length)
    {
        ESP_LOGE(TAG, "Download size mismatch: expected=%d, received=%d", content_length, total_read);
        mbedtls_sha256_free(&sha_ctx);
        return ESP_FAIL;
    }

    uint8_t hash[32];
    if (mbedtls_sha256_finish(&sha_ctx, hash) != 0)
    {
        ESP_LOGE(TAG, "SHA256 finish failed");
        mbedtls_sha256_free(&sha_ctx);
        return ESP_FAIL;
    }
    mbedtls_sha256_free(&sha_ctx);

    // Allocate buffer and copy data
    size_t size = download_buffer.size();
    uint8_t* buffer = (uint8_t*)malloc(size);
    if (buffer == nullptr)
    {
        ESP_LOGE(TAG, "Failed to allocate %d bytes", size);
        return ESP_ERR_NO_MEM;
    }

    memcpy(buffer, download_buffer.data(), size);

    *out_buffer = buffer;
    *out_size = size;

    ESP_LOGI(TAG, "Firmware downloaded: %d bytes", size);
    return ESP_OK;
}

} // namespace fota
