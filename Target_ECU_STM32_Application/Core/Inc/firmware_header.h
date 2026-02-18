#ifndef FIRMWARE_HEADER_H
#define FIRMWARE_HEADER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dual Slot Architecture:
 * - METADATA_A: 0x08007800 (1KB) - Slot A header
 * - SLOT_A:     0x08007C00 (16KB) - Active firmware
 * Application reads metadata from METADATA_A address
 */
#define FW_HEADER_ADDR        (0x08007800UL)  /* METADATA_A_ADDR */
#define FW_HEADER_MAGIC       (0x41544F46UL)  /* 'FOTA' */
#define FW_HEADER_SIZE        (164U)          /* Full header with AES support */

#if defined(__CC_ARM)
__packed typedef struct
{
  uint32_t magic;              /* 'FOTA' */
  char     version[12];        /* ASCII version */
  uint32_t firmware_size;      /* bytes */
  uint8_t  sha256[32];         /* SHA-256 hash */
  uint8_t  signature[64];      /* ECDSA signature */
  uint8_t  aes_iv[16];         /* AES-128-CBC IV */
  uint8_t  original_sha256[32]; /* Plaintext SHA-256 (if encrypted) */
} firmware_header_t;
#else
typedef struct __attribute__((packed))
{
  uint32_t magic;              /* 'FOTA' */
  char     version[12];        /* ASCII version */
  uint32_t firmware_size;      /* bytes */
  uint8_t  sha256[32];         /* SHA-256 hash */
  uint8_t  signature[64];      /* ECDSA signature */
  uint8_t  aes_iv[16];         /* AES-128-CBC IV */
  uint8_t  original_sha256[32]; /* Plaintext SHA-256 (if encrypted) */
} firmware_header_t;
#endif

static inline const firmware_header_t* FW_Header_Get(void)
{
  return (const firmware_header_t*)FW_HEADER_ADDR;
}

static inline const char* FW_Header_GetVersion(void)
{
  const firmware_header_t* hdr = FW_Header_Get();
  if (hdr != 0 && hdr->magic == FW_HEADER_MAGIC)
  {
    return hdr->version;
  }
  return "0.0.0";
}

#ifdef __cplusplus
}
#endif

#endif /* FIRMWARE_HEADER_H */
