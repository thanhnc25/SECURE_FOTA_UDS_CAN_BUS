/**
 ******************************************************************************
 * @file    aes_decrypt.h
 * @brief   AES-128-CBC Decryption for FOTA Firmware
 * @note    Requires tiny-AES-c library or similar
 ******************************************************************************
 */

#ifndef AES_DECRYPT_H
#define AES_DECRYPT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Decrypt firmware using AES-128-CBC
 * @param encrypted_data: Pointer to encrypted firmware data
 * @param size: Size of encrypted data (must be multiple of 16)
 * @param iv: 16-byte AES Initialization Vector from header
 * @param output: Output buffer (must be at least 'size' bytes)
 * @return 0 on success, -1 on error
 * 
 * @note This function uses AES_KEY defined in aes_key.h
 * @note Output buffer can be the same as input for in-place decryption
 */
int aes_decrypt_firmware(const uint8_t* encrypted_data, 
                        uint32_t size,
                        const uint8_t iv[16],
                        uint8_t* output);

/**
 * @brief Remove PKCS7 padding after decryption
 * @param data: Decrypted data with PKCS7 padding
 * @param size: Total size including padding
 * @return Actual size without padding, or 0 on error
 * 
 * @note Call this after aes_decrypt_firmware to get actual firmware size
 * @example
 *   uint32_t decrypted_size = aes_remove_pkcs7_padding(buffer, encrypted_size);
 *   if (decrypted_size > 0) {
 *       // buffer now contains decrypted firmware of size decrypted_size
 *   }
 */
uint32_t aes_remove_pkcs7_padding(const uint8_t* data, uint32_t size);

/**
 * @brief Decrypt firmware in blocks (for limited RAM)
 * @param encrypted_data: Pointer to encrypted firmware data
 * @param total_size: Total encrypted size
 * @param iv: 16-byte AES IV from header
 * @param block_callback: Callback function for each decrypted block
 *        void callback(const uint8_t* block, uint32_t size, uint32_t offset, void* user_data)
 * @param user_data: User data passed to callback
 * @return 0 on success, -1 on error
 * 
 * @note Use this when RAM is insufficient to hold entire firmware
 * @note Callback is called for each 1KB block
 */
typedef void (*aes_block_callback_t)(const uint8_t* block, uint32_t size, 
                                    uint32_t offset, void* user_data);

int aes_decrypt_firmware_blocks(const uint8_t* encrypted_data,
                               uint32_t total_size,
                               const uint8_t iv[16],
                               aes_block_callback_t callback,
                               void* user_data);

#ifdef __cplusplus
}
#endif

#endif /* AES_DECRYPT_H */
