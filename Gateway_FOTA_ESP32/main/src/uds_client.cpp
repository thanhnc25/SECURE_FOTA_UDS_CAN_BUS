#include "fota/uds_client.hpp"

#include <algorithm>
#include <cstring>
#include <vector>

#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "can_driver.h"
#include "cantp/cantp.hpp"

namespace fota
{
static const char* const TAG = "FOTA_UDS";

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

static esp_err_t isotp_send(uint32_t tx_id, uint32_t rx_fc_id, const uint8_t* payload, size_t len, uint32_t timeout_ms)
{
    cantp::Config cfg;
    cfg.tx_id = tx_id;
    cfg.rx_fc_id = rx_fc_id;
    cfg.tx_timeout_ms = timeout_ms;
    cfg.wait_fc_timeout_ms = 3000U;
    cfg.accept_fc_from_any_id = false;
    cfg.log_rx_while_waiting = false;

    return cantp::send_isotp(payload, len, cfg);
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
        // Extended length: 0x10 0x00 [len BE 4 bytes] data at [6] (2 bytes)
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

static esp_err_t uds_request(const UdsConfig& cfg,
                             const uint8_t* req,
                             size_t req_len,
                             std::vector<uint8_t>* out_resp)
{
    if (req == nullptr || req_len == 0U || out_resp == nullptr)
    {
        return ESP_ERR_INVALID_ARG;
    }

    // Send request (ISO-TP)
    esp_err_t err = isotp_send(cfg.tx_id, cfg.rx_id, req, req_len, 50U);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "ISO-TP send failed: %s", esp_err_to_name(err));
        return err;
    }

    // Receive response (ISO-TP) with NRC 0x78 (Response Pending) retry logic
    // NRC 0x78 means ECU is processing and needs more time
    const uint32_t max_nrc78_retries = 10U;  // Max 10 retries = ~30 seconds total
    uint32_t nrc78_count = 0U;
    
    while (true)
    {
        err = isotp_recv(cfg.rx_id, cfg.tx_id, cfg.can_timeout_ms, out_resp);
        if (err != ESP_OK)
        {
            ESP_LOGE(TAG, "ISO-TP recv failed: %s", esp_err_to_name(err));
            return err;
        }

        if (out_resp->empty())
        {
            return ESP_FAIL;
        }

        // Handle negative response: 0x7F <SID> <NRC>
        if ((*out_resp)[0] == 0x7FU && out_resp->size() >= 3U)
        {
            const uint8_t nrc_code = (*out_resp)[2];
            
            // NRC 0x78 = Response Pending (ECU still processing, wait and retry)
            if (nrc_code == 0x78U)
            {
                nrc78_count++;
                if (nrc78_count > max_nrc78_retries)
                {
                    ESP_LOGE(TAG, "UDS Response Pending timeout (received %u NRC 0x78)", (unsigned)nrc78_count);
                    return ESP_ERR_TIMEOUT;
                }
                
                ESP_LOGI(TAG, "UDS Response Pending (NRC 0x78), waiting... (%u/%u)", (unsigned)nrc78_count, (unsigned)max_nrc78_retries);
                // Continue waiting for actual response
                out_resp->clear();
                continue;
            }
            else
            {
                // Other negative responses are errors
                ESP_LOGE(TAG, "UDS Negative Response: SID=0x%02X NRC=0x%02X", (unsigned)(*out_resp)[1], (unsigned)nrc_code);
                return ESP_FAIL;
            }
        }
        
        // Got valid response, break out of retry loop
        break;
    }

    const uint8_t expected_pos = (uint8_t)(req[0] + 0x40U);
    if ((*out_resp)[0] != expected_pos)
    {
        ESP_LOGE(TAG, "Unexpected UDS response: got=0x%02X expected=0x%02X", (unsigned)(*out_resp)[0],
                 (unsigned)expected_pos);
        return ESP_FAIL;
    }

    return ESP_OK;
}

static void be32(uint8_t out[4], uint32_t v)
{
    out[0] = (uint8_t)((v >> 24) & 0xFFU);
    out[1] = (uint8_t)((v >> 16) & 0xFFU);
    out[2] = (uint8_t)((v >> 8) & 0xFFU);
    out[3] = (uint8_t)((v >> 0) & 0xFFU);
}

esp_err_t uds_download_firmware(const UdsConfig& cfg, const uint8_t* firmware, size_t firmware_len)
{
    if (firmware == nullptr || firmware_len == 0U)
    {
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(TAG, "UDS start download: len=%u", (unsigned)firmware_len);

    // 1) Diagnostic Session Control: 0x10 0x02
    {
        const uint8_t req[] = {0x10U, 0x02U};
        std::vector<uint8_t> resp;
        esp_err_t err = uds_request(cfg, req, sizeof(req), &resp);
        if (err != ESP_OK)
        {
            ESP_LOGE(TAG, "0x10 0x02 failed");
            return err;
        }
        ESP_LOGI(TAG, "Programming session OK");
    }

    /* If ECU was running Application, it may respond 0x50 0x02 and then reset
     * into bootloader. Give it a short time to come back before 0x34.
     */
    vTaskDelay(pdMS_TO_TICKS(250));

    // 2) Request Download: 0x34
    {
        // dataFormatIdentifier=0x00, addressAndLengthFormatIdentifier=0x44 (4 bytes addr, 4 bytes size)
        std::vector<uint8_t> req;
        req.reserve(1 + 1 + 1 + 4 + 4);
        req.push_back(0x34U);
        req.push_back(0x00U);
        req.push_back(0x44U);

        uint8_t addr_be[4];
        uint8_t size_be[4];
        be32(addr_be, cfg.download_address);
        be32(size_be, (uint32_t)firmware_len);

        req.insert(req.end(), addr_be, addr_be + 4);
        req.insert(req.end(), size_be, size_be + 4);

        std::vector<uint8_t> resp;
        esp_err_t err = uds_request(cfg, req.data(), req.size(), &resp);
        if (err != ESP_OK)
        {
            ESP_LOGE(TAG, "RequestDownload failed");
            return err;
        }

        // Many ECUs (including our STM32 bootloader) return:
        //   0x74 <lenFormatId> <maxNumberOfBlockLength>
        // where maxNumberOfBlockLength is the maximum *data payload* in 0x36 (excluding SID+BSN).
        size_t ecu_max_payload = 0U;
        if (resp.size() >= 3U)
        {
            ecu_max_payload = (size_t)resp[2];
        }
        if (ecu_max_payload == 0U)
        {
            ecu_max_payload = cfg.transfer_block_payload;
        }

        ESP_LOGI(TAG, "RequestDownload OK (ecu_max_payload=%u, cfg_payload=%u)",
                 (unsigned)ecu_max_payload,
                 (unsigned)cfg.transfer_block_payload);

        // 3) Transfer Data: 0x36
        {
            size_t offset = 0U;
            uint8_t bsn = 1U;

            const size_t block_payload = std::max<size_t>(1U, std::min(cfg.transfer_block_payload, ecu_max_payload));

            while (offset < firmware_len)
            {
                const size_t chunk = std::min<size_t>(block_payload, firmware_len - offset);

                std::vector<uint8_t> req;
                req.reserve(2 + chunk);
                req.push_back(0x36U);
                req.push_back(bsn);
                req.insert(req.end(), firmware + offset, firmware + offset + chunk);

                std::vector<uint8_t> resp;
                esp_err_t err2 = uds_request(cfg, req.data(), req.size(), &resp);
                if (err2 != ESP_OK)
                {
                    ESP_LOGE(TAG, "TransferData failed at offset=%u", (unsigned)offset);
                    return err2;
                }

                if (resp.size() < 2U || resp[1] != bsn)
                {
                    ESP_LOGE(TAG, "TransferData bad BSN (got %u expected %u)",
                             (unsigned)(resp.size() >= 2U ? resp[1] : 0U),
                             (unsigned)bsn);
                    return ESP_FAIL;
                }

                offset += chunk;
                bsn++;
                if (bsn == 0U)
                {
                    bsn = 1U;
                }

                if ((offset <= (3U * block_payload)) || (offset % (32U * block_payload) == 0U) || (offset == firmware_len))
                {
                    ESP_LOGI(TAG, "Transfer progress: %u/%u", (unsigned)offset, (unsigned)firmware_len);
                }
            }

            ESP_LOGI(TAG, "TransferData OK");
        }
    }

    // 4) Request Transfer Exit: 0x37
    {
        const uint8_t req[] = {0x37U};
        std::vector<uint8_t> resp;
        esp_err_t err = uds_request(cfg, req, sizeof(req), &resp);
        if (err != ESP_OK)
        {
            ESP_LOGE(TAG, "RequestTransferExit failed");
            return err;
        }
        ESP_LOGI(TAG, "RequestTransferExit OK");
    }

    ESP_LOGI(TAG, "UDS download completed");
    return ESP_OK;
}

esp_err_t uds_read_version(const UdsConfig& cfg, char* version_out, size_t max_len)
{
    if (version_out == nullptr || max_len == 0U)
    {
        return ESP_ERR_INVALID_ARG;
    }

    version_out[0] = '\0';

    // UDS 0x22 - Read Data By Identifier, DID 0xF100
    const uint8_t req[] = {0x22U, 0xF1U, 0x00U};
    std::vector<uint8_t> resp;

    esp_err_t err = uds_request(cfg, req, sizeof(req), &resp);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "UDS 0x22 failed");
        return err;
    }

    // Expected response: 0x62 0xF1 0x00 [version_string]
    if (resp.size() < 4U || resp[0] != 0x62U || resp[1] != 0xF1U || resp[2] != 0x00U)
    {
        ESP_LOGE(TAG, "Invalid version response");
        return ESP_FAIL;
    }

    // Copy version string
    const size_t version_len = std::min(resp.size() - 3U, max_len - 1U);
    for (size_t i = 0; i < version_len; i++)
    {
        version_out[i] = (char)resp[3 + i];
    }
    version_out[version_len] = '\0';

    ESP_LOGI(TAG, "Version read: %s", version_out);
    return ESP_OK;
}

} // namespace fota
