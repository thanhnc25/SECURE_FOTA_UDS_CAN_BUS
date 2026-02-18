/**
 ******************************************************************************
 * @file    dual_slot_manager.c
 * @brief   Dual Slot Management Functions for A/B Firmware Update
 * @author  Secure FOTA System
 * @date    Feb 2026
 ******************************************************************************
 */

#include "dual_slot_manager.h"
#include "dual_slot_config.h"
#include "fota_security.h"
#include "sha256_minimal.h"
#include "stm32f1xx_hal.h"
#include <string.h>

/* External log functions */
extern void Log_Str(const char* s);
extern void Log_TagU32(const char* tag, uint32_t val);
extern void Log_TagHex32(const char* tag, uint32_t val);
extern void Flash_Erase(uint32_t address);
extern void Flash_Write(uint32_t addr, const uint8_t* data, uint32_t len);

/**
 * @brief  Read FOTA header from metadata page
 * @param  metadata_addr: Address of metadata page (METADATA_A_ADDR or METADATA_B_ADDR)
 * @retval Pointer to header (read-only), or NULL if invalid
 */
const fota_header_t* DualSlot_ReadHeader(uint32_t metadata_addr)
{
    const fota_header_t* hdr = (const fota_header_t*)metadata_addr;
    
    if (hdr->magic != FOTA_MAGIC)
    {
        return NULL;
    }
    
    if (hdr->firmware_size == 0 || hdr->firmware_size > MAX_FIRMWARE_SIZE)
    {
        return NULL;
    }
    
    return hdr;
}

/**
 * @brief  Verify firmware in a slot (SHA-256 + ECDSA) - OPTIMIZED
 * @note   Uses chunked SHA-256 processing (256 bytes) to minimize RAM usage
 * @param  slot_addr: Start address of slot (SLOT_A_ADDR or SLOT_B_ADDR)
 * @param  metadata_addr: Address of corresponding metadata page
 * @retval 1 if valid, 0 if invalid
 */
uint8_t DualSlot_VerifySlot(uint32_t slot_addr, uint32_t metadata_addr)
{
    const fota_header_t* hdr = DualSlot_ReadHeader(metadata_addr);
    if (hdr == NULL)
    {
        Log_Str("DualSlot: Invalid header\r\n");
        return 0;
    }
    
    /* Size validation */
    if (hdr->firmware_size == 0 || hdr->firmware_size > MAX_FIRMWARE_SIZE)
    {
        Log_Str("DualSlot: Invalid size\r\n");
        return 0;
    }
    
    /* Calculate SHA-256 of firmware using chunked processing */
    uint8_t hash[32];
    if (fota_compute_sha256((const uint8_t*)slot_addr, hdr->firmware_size, hash) != 0)
    {
        Log_Str("DualSlot: SHA256 calc failed\r\n");
        return 0;
    }
    
    /* Compare hash */
    if (memcmp(hash, hdr->sha256, 32) != 0)
    {
        Log_Str("DualSlot: SHA256 mismatch\r\n");
        return 0;
    }
    
    /* Verify ECDSA signature (uses cached public key) */
    if (fota_verify_ecdsa(hash, hdr->signature) != 0)
    {
        Log_Str("DualSlot: ECDSA failed\r\n");
        return 0;
    }
    
    Log_Str("DualSlot: Slot valid\r\n");
    return 1;
}

/**
 * @brief  Copy Slot B ? Slot A (after successful download)
 * @note   ATOMIC UPDATE with power-loss recovery:
 *         - State COPY_PENDING: Slot B verified, about to erase Slot A
 *         - State COPY_IN_PROGRESS: Erasing/copying in progress
 *         - State COPY_COMPLETE: Copy finished, safe to boot
 * @retval 1 if success, 0 if failed
 */
uint8_t DualSlot_CopyBtoA(void)
{
    Log_Str("DualSlot: Copy B->A start\r\n");
    
    /* Step 0: Validate Slot B before starting */
    const fota_header_t* hdr_b = DualSlot_ReadHeader(METADATA_B_ADDR);
    if (hdr_b == NULL)
    {
        Log_Str("DualSlot: Slot B invalid header\r\n");
        return 0;
    }
    
    uint32_t fw_size = hdr_b->firmware_size;
    Log_TagU32("DualSlot: FW size=", fw_size);
    
    /* ===================================================================
     * ATOMIC STATE: COPY_PENDING
     * Slot B is verified, we are about to erase Slot A.
     * If power loss happens here, boot will detect COPY_PENDING and
     * restart the copy process (Slot B is still intact).
     * =================================================================== */
    __HAL_RCC_PWR_CLK_ENABLE();
    __HAL_RCC_BKP_CLK_ENABLE();
    HAL_PWR_EnableBkUpAccess();
    BKP->DR2 = UPDATE_STATE_COPY_PENDING;
    Log_Str("State: COPY_PENDING\r\n");
    HAL_Delay(10);  /* Ensure write completes */
    
    /* ===================================================================
     * ATOMIC STATE: COPY_IN_PROGRESS
     * Now erasing Slot A. If power loss here, boot will detect this
     * state and restart copy from Slot B (which is still valid).
     * =================================================================== */
    BKP->DR2 = UPDATE_STATE_COPY_IN_PROGRESS;
    Log_Str("State: COPY_IN_PROGRESS\r\n");
    HAL_Delay(10);  /* Ensure write completes */
    
    /* Step 1: Erase Slot A + Metadata A */
    HAL_FLASH_Unlock();
    
    /* Erase Metadata A */
    Flash_Erase(METADATA_A_ADDR);
    
    /* Erase Slot A (page by page) */
    uint32_t slot_a_end = SLOT_A_ADDR + fw_size;
    if (slot_a_end > (SLOT_A_ADDR + SLOT_A_SIZE))
    {
        slot_a_end = SLOT_A_ADDR + SLOT_A_SIZE;
    }
    
    for (uint32_t addr = SLOT_A_ADDR; addr < slot_a_end; addr += FLASH_PAGE_SIZE)
    {
        Flash_Erase(addr);
    }
    
    /* Step 2: Copy Metadata B ? Metadata A */
    Flash_Write(METADATA_A_ADDR, (const uint8_t*)METADATA_B_ADDR, FOTA_HEADER_SIZE);
    
    /* Step 3: Copy Slot B → Slot A with read-back verification */
    const uint32_t COPY_CHUNK_SIZE = 256;
    for (uint32_t offset = 0; offset < fw_size; offset += COPY_CHUNK_SIZE)
    {
        uint32_t chunk_len = COPY_CHUNK_SIZE;
        if (offset + chunk_len > fw_size)
        {
            chunk_len = fw_size - offset;
        }
        
        const uint8_t* src = (const uint8_t*)(SLOT_B_ADDR + offset);
        Flash_Write(SLOT_A_ADDR + offset, src, chunk_len);
        
        /* Read-back verification for critical safety */
        const uint8_t* dst = (const uint8_t*)(SLOT_A_ADDR + offset);
        if (memcmp(src, dst, chunk_len) != 0)
        {
            HAL_FLASH_Lock();
            Log_Str("ERR: Copy verification failed\r\n");
            Log_TagU32("Offset=", offset);
            return 0;
        }
    }
    
    HAL_FLASH_Lock();
    
    /* ===================================================================
     * ATOMIC STATE: COPY_COMPLETE
     * Copy finished successfully. Slot A now contains new firmware.
     * Boot process will clear this state and jump to Slot A.
     * =================================================================== */
    BKP->DR2 = UPDATE_STATE_COPY_COMPLETE;
    Log_Str("State: COPY_COMPLETE\r\n");
    HAL_Delay(10);  /* Ensure write completes */
    
    Log_Str("DualSlot: Copy complete\r\n");
    Log_Str("DualSlot: Slot A ready to boot\r\n");
    return 1;
}

/**
 * @brief  Get slot information
 * @param  slot_addr: SLOT_A_ADDR or SLOT_B_ADDR
 * @param  metadata_addr: Corresponding metadata address
 * @param  info: Output slot info structure
 * @retval None
 */
void DualSlot_GetInfo(uint32_t slot_addr, uint32_t metadata_addr, slot_info_t* info)
{
    if (info == NULL)
    {
        return;
    }
    
    info->status = SLOT_INVALID;
    info->firmware_size = 0;
    memset(info->version, 0, sizeof(info->version));
    
    const fota_header_t* hdr = DualSlot_ReadHeader(metadata_addr);
    if (hdr == NULL)
    {
        return;
    }
    
    info->firmware_size = hdr->firmware_size;
    memcpy(info->version, hdr->version, sizeof(hdr->version));
    
    /* Verify to determine if actually valid */
    if (DualSlot_VerifySlot(slot_addr, metadata_addr))
    {
        info->status = SLOT_VALID;
    }
    else
    {
        info->status = SLOT_PENDING;
    }
}

/**
 * @brief  Erase Slot B + Metadata B (prepare for new download)
 * @retval None
 */
void DualSlot_EraseSlotB(void)
{
    Log_Str("DualSlot: Erase Slot B\r\n");
    
    HAL_FLASH_Unlock();
    
    /* Erase Metadata B */
    Flash_Erase(METADATA_B_ADDR);
    
    /* Erase all Slot B pages */
    for (uint32_t addr = SLOT_B_ADDR; addr < (SLOT_B_ADDR + SLOT_B_SIZE); addr += FLASH_PAGE_SIZE)
    {
        Flash_Erase(addr);
    }
    
    HAL_FLASH_Lock();
    
    Log_Str("DualSlot: Slot B erased\r\n");
}

/**
 * @brief  Check if Slot A has valid bootable firmware
 * @retval 1 if valid, 0 otherwise
 */
uint8_t DualSlot_IsSlotABootable(void)
{
    /* Check vector table sanity */
    const uint32_t sp = *(volatile uint32_t*)SLOT_A_ADDR;
    const uint32_t pc = *(volatile uint32_t*)(SLOT_A_ADDR + 4);
    
    /* Stack pointer must be in SRAM */
    if ((sp & 0x2FFE0000UL) != 0x20000000UL)
    {
        return 0;
    }
    
    /* Reset handler must be Thumb code in flash */
    if ((pc & 1UL) == 0UL)
    {
        return 0;
    }
    
    const uint32_t pc_addr = pc & ~1UL;
    if (pc_addr < SLOT_A_ADDR || pc_addr > (SLOT_A_ADDR + SLOT_A_SIZE))
    {
        return 0;
    }
    
    /* Verify firmware integrity */
    return DualSlot_VerifySlot(SLOT_A_ADDR, METADATA_A_ADDR);
}
