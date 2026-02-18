/**
 ******************************************************************************
 * @file    dual_slot_manager.h
 * @brief   Dual Slot Management Functions Header
 * @author  Secure FOTA System
 * @date    Feb 2026
 ******************************************************************************
 */

#ifndef DUAL_SLOT_MANAGER_H
#define DUAL_SLOT_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "dual_slot_config.h"
#include "stm32f1xx_hal.h"  /* For BKP register access */
#include <stdint.h>

/**
 * @brief  Read FOTA header from metadata page
 * @param  metadata_addr: Address of metadata page
 * @retval Pointer to header, or NULL if invalid
 */
const fota_header_t* DualSlot_ReadHeader(uint32_t metadata_addr);

/**
 * @brief  Verify firmware in a slot (SHA-256 + ECDSA)
 * @param  slot_addr: Start address of slot
 * @param  metadata_addr: Address of corresponding metadata page
 * @retval 1 if valid, 0 if invalid
 */
uint8_t DualSlot_VerifySlot(uint32_t slot_addr, uint32_t metadata_addr);

/**
 * @brief  Copy Slot B → Slot A (safe update)
 * @retval 1 if success, 0 if failed
 */
uint8_t DualSlot_CopyBtoA(void);

/**
 * @brief  Get slot information
 * @param  slot_addr: SLOT_A_ADDR or SLOT_B_ADDR
 * @param  metadata_addr: Corresponding metadata address
 * @param  info: Output slot info structure
 */
void DualSlot_GetInfo(uint32_t slot_addr, uint32_t metadata_addr, slot_info_t* info);

/**
 * @brief  Erase Slot B + Metadata B (prepare for download)
 */
void DualSlot_EraseSlotB(void);

/**
 * @brief  Check if Slot A has valid bootable firmware
 * @retval 1 if valid, 0 otherwise
 */
uint8_t DualSlot_IsSlotABootable(void);

#ifdef __cplusplus
}
#endif

#endif /* DUAL_SLOT_MANAGER_H */
