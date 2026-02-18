/**
 ******************************************************************************
 * @file    aes_decrypt.c
 * @brief   AES-128-CBC Decryption Implementation for FOTA
 * @note    Uses tiny-AES-c library
 ******************************************************************************
 */

#include "aes_decrypt.h"
#include "aes.h"           // tiny-AES-c library
#include "aes_key.h"       // Generated AES key from Python server
#include <string.h>

/**
 * @brief Decrypt firmware using AES-128-CBC
 */
int aes_decrypt_firmware(const uint8_t* encrypted_data, 
                        uint32_t size,
                        const uint8_t iv[16],
                        uint8_t* output)
{
    if (encrypted_data == NULL || output == NULL || iv == NULL) {
        return -1;
    }
    
    /* Size must be multiple of 16 (AES block size) */
    if (size == 0 || (size % 16) != 0) {
        return -1;
    }
    
    /* Copy IV (AES will modify it during decryption) */
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    
    /* Copy encrypted data to output buffer if not in-place */
    if (output != encrypted_data) {
        memcpy(output, encrypted_data, size);
    }
    
    /* Initialize AES context */
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, AES_KEY, iv_copy);
    
    /* Decrypt in-place */
    AES_CBC_decrypt_buffer(&ctx, output, size);
    
    return 0;
}

/**
 * @brief Remove PKCS7 padding after decryption
 */
uint32_t aes_remove_pkcs7_padding(const uint8_t* data, uint32_t size)
{
    if (data == NULL || size == 0) {
        return 0;
    }
    
    /* Get padding value (last byte) */
    uint8_t padding = data[size - 1];
    
    /* Validate padding value */
    if (padding == 0 || padding > 16) {
        return 0;  /* Invalid padding */
    }
    
    /* Check if we have enough bytes */
    if (size < padding) {
        return 0;  /* Invalid padding */
    }
    
    /* Verify all padding bytes are correct */
    for (uint32_t i = size - padding; i < size; i++) {
        if (data[i] != padding) {
            return 0;  /* Invalid padding */
        }
    }
    
    return size - padding;
}

/**
 * @brief Decrypt firmware in blocks (for limited RAM)
 */
int aes_decrypt_firmware_blocks(const uint8_t* encrypted_data,
                               uint32_t total_size,
                               const uint8_t iv[16],
                               aes_block_callback_t callback,
                               void* user_data)
{
    if (encrypted_data == NULL || iv == NULL || callback == NULL) {
        return -1;
    }
    
    if (total_size == 0 || (total_size % 16) != 0) {
        return -1;
    }
    
    /* Block size for processing (must be multiple of 16) */
    #define DECRYPT_BLOCK_SIZE 1024  /* 1KB blocks */
    
    uint8_t block_buffer[DECRYPT_BLOCK_SIZE];
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    
    /* Initialize AES context */
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, AES_KEY, iv_copy);
    
    /* Process in blocks */
    uint32_t offset = 0;
    while (offset < total_size) {
        uint32_t block_size = (total_size - offset) > DECRYPT_BLOCK_SIZE ? 
                             DECRYPT_BLOCK_SIZE : (total_size - offset);
        
        /* Ensure block size is multiple of 16 */
        if (block_size % 16 != 0) {
            return -1;
        }
        
        /* Copy encrypted block */
        memcpy(block_buffer, encrypted_data + offset, block_size);
        
        /* Decrypt block */
        AES_CBC_decrypt_buffer(&ctx, block_buffer, block_size);
        
        /* Call user callback with decrypted block */
        callback(block_buffer, block_size, offset, user_data);
        
        offset += block_size;
    }
    
    return 0;
}

/**
 * @brief Example callback for block decryption - Flash to memory
 */
#if 0  /* Example code - uncomment if needed */
void flash_block_callback(const uint8_t* block, uint32_t size, 
                         uint32_t offset, void* user_data)
{
    uint32_t* flash_addr_ptr = (uint32_t*)user_data;
    uint32_t flash_addr = *flash_addr_ptr + offset;
    
    /* Flash the decrypted block */
    for (uint32_t i = 0; i < size; i += 4) {
        uint32_t word = *(uint32_t*)(block + i);
        HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, flash_addr + i, word);
    }
}

/* Usage example:
 * uint32_t flash_base = 0x08008000;
 * aes_decrypt_firmware_blocks(encrypted_data, size, iv, 
 *                            flash_block_callback, &flash_base);
 */
#endif
