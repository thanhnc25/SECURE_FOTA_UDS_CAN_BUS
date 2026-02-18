#!/usr/bin/env python3
"""
Crypto Utilities for Secure FOTA Manager
Handles ECDSA key generation, signing, and verification + AES-128 encryption
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import hashlib
import os
from pathlib import Path


class CryptoManager:
    """Manage cryptographic operations for FOTA"""
    
    def __init__(self, keys_dir="keys"):
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(exist_ok=True)
        
        self.private_key = None
        self.public_key = None
        
        self.private_key_path = self.keys_dir / "private_key.pem"
        self.public_key_path = self.keys_dir / "public_key.pem"
        
        # AES-128 key for firmware encryption
        self.aes_key_path = self.keys_dir / "aes_key.bin"
        self.aes_key = None
        
    def generate_keypair(self):
        """
        Generate ECDSA key pair using SECP256R1 curve (NIST P-256)
        Returns: (private_key, public_key)
        """
        # Generate private key using SECP256R1 curve (NIST P-256 - Compatible with ESP32/STM32)
        private_key = ec.generate_private_key(
            ec.SECP256R1(),
            default_backend()
        )
        
        # Derive public key from private key
        public_key = private_key.public_key()
        
        self.private_key = private_key
        self.public_key = public_key
        
        return private_key, public_key
    
    def save_keys(self, private_key=None, public_key=None):
        """
        Save keys to PEM files
        """
        if private_key is None:
            private_key = self.private_key
        if public_key is None:
            public_key = self.public_key
            
        if private_key is None or public_key is None:
            raise ValueError("Keys not generated. Call generate_keypair() first.")
        
        # Save private key (with encryption recommended in production)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # No password for simplicity
        )
        
        with open(self.private_key_path, 'wb') as f:
            f.write(private_pem)
            
        # Save public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(self.public_key_path, 'wb') as f:
            f.write(public_pem)
            
        return self.private_key_path, self.public_key_path
    
    def load_keys(self):
        """
        Load keys from PEM files
        Returns: (private_key, public_key)
        """
        if not self.private_key_path.exists():
            raise FileNotFoundError(f"Private key not found: {self.private_key_path}")
        if not self.public_key_path.exists():
            raise FileNotFoundError(f"Public key not found: {self.public_key_path}")
        
        # Load private key
        with open(self.private_key_path, 'rb') as f:
            private_pem = f.read()
            self.private_key = serialization.load_pem_private_key(
                private_pem,
                password=None,
                backend=default_backend()
            )
        
        # Load public key
        with open(self.public_key_path, 'rb') as f:
            public_pem = f.read()
            self.public_key = serialization.load_pem_public_key(
                public_pem,
                backend=default_backend()
            )
            
        return self.private_key, self.public_key
    
    def calculate_sha256(self, data):
        """
        Calculate SHA-256 hash of data
        Args:
            data: bytes or file path
        Returns: bytes (32 bytes hash)
        """
        if isinstance(data, (str, Path)):
            # If data is a file path
            with open(data, 'rb') as f:
                return hashlib.sha256(f.read()).digest()
        else:
            # If data is bytes
            return hashlib.sha256(data).digest()

    def calculate_sha256_skip_header(self, data, header_offset=0x100, header_len=0x80):
        """
        Calculate SHA-256 excluding header region.
        Hash = data[0:header_offset] + data[header_offset+header_len:]
        """
        if isinstance(data, (str, Path)):
            with open(data, 'rb') as f:
                blob = f.read()
        else:
            blob = data

        if blob is None or len(blob) <= (header_offset + header_len):
            raise ValueError("Firmware too small for header exclusion")

        h = hashlib.sha256()
        h.update(blob[:header_offset])
        h.update(blob[header_offset + header_len:])
        return h.digest()
    
    def sign_data(self, data, private_key=None):
        """
        Sign data using ECDSA with private key
        Args:
            data: bytes or file path to sign
            private_key: optional private key (uses loaded key if None)
        Returns: bytes (64-byte raw signature: r || s)
        """
        if private_key is None:
            private_key = self.private_key
            
        if private_key is None:
            raise ValueError("Private key not loaded. Call load_keys() or generate_keypair() first.")
        
        # Calculate hash first
        if isinstance(data, (str, Path)):
            hash_value = self.calculate_sha256(data)
        else:
            hash_value = hashlib.sha256(data).digest()
        
        # Sign the hash (returns DER format)
        # Use Prehashed because we already computed SHA256 above
        signature_der = private_key.sign(
            hash_value,
            ec.ECDSA(Prehashed(hashes.SHA256()))
        )
        
        # Convert DER signature to raw (r || s) format for embedded systems
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        r, s = decode_dss_signature(signature_der)
        
        # Convert r and s to 32-byte big-endian format
        r_bytes = r.to_bytes(32, byteorder='big')
        s_bytes = s.to_bytes(32, byteorder='big')
        
        # Return concatenated 64-byte signature
        return r_bytes + s_bytes

    def sign_data_skip_header(self, data, private_key=None, header_offset=0x100, header_len=0x80):
        """
        Sign firmware data excluding header region.
        Returns raw 64-byte signature (r||s).
        """
        if private_key is None:
            private_key = self.private_key

        if private_key is None:
            raise ValueError("Private key not loaded. Call load_keys() or generate_keypair() first.")

        if isinstance(data, (str, Path)):
            hash_value = self.calculate_sha256_skip_header(data, header_offset, header_len)
        else:
            hash_value = self.calculate_sha256_skip_header(data, header_offset, header_len)

        signature_der = private_key.sign(
            hash_value,
            ec.ECDSA(Prehashed(hashes.SHA256()))
        )

        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        r, s = decode_dss_signature(signature_der)
        r_bytes = r.to_bytes(32, byteorder='big')
        s_bytes = s.to_bytes(32, byteorder='big')
        return r_bytes + s_bytes
    
    def verify_signature(self, data, signature, public_key=None):
        """
        Verify ECDSA signature
        Args:
            data: bytes or file path
            signature: bytes (64-byte raw signature: r || s, or DER format)
            public_key: optional public key (uses loaded key if None)
        Returns: bool (True if valid, False otherwise)
        """
        if public_key is None:
            public_key = self.public_key
            
        if public_key is None:
            raise ValueError("Public key not loaded. Call load_keys() first.")
        
        # Calculate hash
        if isinstance(data, (str, Path)):
            hash_value = self.calculate_sha256(data)
        else:
            hash_value = hashlib.sha256(data).digest()
        
        try:
            # If signature is 64 bytes, convert from raw (r || s) to DER
            if len(signature) == 64:
                from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
                r = int.from_bytes(signature[:32], byteorder='big')
                s = int.from_bytes(signature[32:], byteorder='big')
                signature = encode_dss_signature(r, s)
            
            # Use Prehashed because hash_value is already SHA256
            public_key.verify(
                signature,
                hash_value,
                ec.ECDSA(Prehashed(hashes.SHA256()))
            )
            return True
        except InvalidSignature:
            return False
    
    def generate_aes_key(self):
        """
        Generate a random AES-128 key (16 bytes)
        Returns: bytes (16 bytes)
        """
        self.aes_key = os.urandom(16)  # 128 bits = 16 bytes
        return self.aes_key
    
    def save_aes_key(self, aes_key=None):
        """
        Save AES key to file
        Args:
            aes_key: optional AES key (uses generated key if None)
        Returns: Path to saved key file
        """
        if aes_key is None:
            aes_key = self.aes_key
        
        if aes_key is None:
            raise ValueError("AES key not generated. Call generate_aes_key() first.")
        
        if len(aes_key) != 16:
            raise ValueError("AES key must be 16 bytes for AES-128")
        
        with open(self.aes_key_path, 'wb') as f:
            f.write(aes_key)
        
        return self.aes_key_path
    
    def load_aes_key(self):
        """
        Load AES key from file
        Returns: bytes (16 bytes)
        """
        if not self.aes_key_path.exists():
            raise FileNotFoundError(f"AES key not found: {self.aes_key_path}")
        
        with open(self.aes_key_path, 'rb') as f:
            self.aes_key = f.read()
        
        if len(self.aes_key) != 16:
            raise ValueError(f"Invalid AES key size: {len(self.aes_key)}, expected 16 bytes")
        
        return self.aes_key
    
    def encrypt_firmware_aes(self, firmware_data, aes_key=None):
        """
        Encrypt firmware using AES-128-CBC with PKCS7 padding
        Args:
            firmware_data: bytes to encrypt
            aes_key: optional AES key (uses loaded key if None)
        Returns: tuple (encrypted_data: bytes, iv: bytes)
        """
        if aes_key is None:
            aes_key = self.aes_key
        
        if aes_key is None:
            raise ValueError("AES key not loaded. Call load_aes_key() or generate_aes_key() first.")
        
        if len(aes_key) != 16:
            raise ValueError("AES key must be 16 bytes for AES-128")
        
        # Generate random IV (16 bytes for AES-128)
        iv = os.urandom(16)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Apply PKCS7 padding (AES block size is 128 bits = 16 bytes)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(firmware_data) + padder.finalize()
        
        # Encrypt
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        return encrypted_data, iv
    
    def decrypt_firmware_aes(self, encrypted_data, iv, aes_key=None):
        """
        Decrypt firmware using AES-128-CBC
        Args:
            encrypted_data: bytes to decrypt
            iv: 16-byte initialization vector
            aes_key: optional AES key (uses loaded key if None)
        Returns: bytes (decrypted firmware)
        """
        if aes_key is None:
            aes_key = self.aes_key
        
        if aes_key is None:
            raise ValueError("AES key not loaded. Call load_aes_key() first.")
        
        if len(aes_key) != 16:
            raise ValueError("AES key must be 16 bytes for AES-128")
        
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes for AES-128-CBC")
        
        # Create cipher
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        return decrypted_data
    
    def export_aes_key_to_c_header(self, output_path=None, key_name="AES_KEY"):
        """
        Export AES key to C header file for STM32
        Args:
            output_path: Path to save .h file (default: keys/aes_key.h)
            key_name: Name of the constant array in C code
        Returns: Path to generated file
        """
        if self.aes_key is None:
            raise ValueError("AES key not loaded. Call load_aes_key() or generate_aes_key() first.")
        
        if output_path is None:
            output_path = self.keys_dir / "aes_key.h"
        else:
            output_path = Path(output_path)
        
        # Format as C array
        hex_values = []
        for i in range(0, len(self.aes_key), 16):
            chunk = self.aes_key[i:i+16]
            hex_line = "    " + ", ".join([f"0x{b:02X}" for b in chunk])
            hex_values.append(hex_line)
        
        # Generate header content
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        header_content = f"""/*
 * ============================================================================
 * AES-128 Encryption Key for Secure FOTA System
 * ============================================================================
 * Auto-generated by Secure FOTA Manager
 * Generated: {timestamp}
 * 
 * WARNING: DO NOT EDIT THIS FILE MANUALLY!
 * WARNING: KEEP THIS KEY SECRET! DO NOT COMMIT TO VERSION CONTROL!
 * 
 * This file contains the AES-128 key used to decrypt firmware on STM32.
 * ============================================================================
 */

#ifndef AES_KEY_H
#define AES_KEY_H

#include <stdint.h>

/* AES-128 Key (16 bytes) */
const uint8_t {key_name}[16] = {{
{",\n".join(hex_values)}
}};

#endif /* AES_KEY_H */
"""
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(header_content)
        
        return output_path
    
    def export_public_key_hex(self, public_key=None):
        """
        Export public key in hex format for embedding in firmware
        Returns: str (hex string)
        """
        if public_key is None:
            public_key = self.public_key
            
        if public_key is None:
            raise ValueError("Public key not loaded.")
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        return public_bytes.hex()
    
    def export_public_key_raw(self, public_key=None):
        """
        Export raw public key bytes (without 0x04 prefix) for embedded systems
        Returns: bytes (64 bytes for SECP256K1)
        """
        if public_key is None:
            public_key = self.public_key
            
        if public_key is None:
            raise ValueError("Public key not loaded.")
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        # Remove 0x04 prefix, return only X and Y coordinates (64 bytes)
        return public_bytes[1:]
    
    def export_to_c_header(self, output_path=None, key_name="ECU_PUBLIC_KEY"):
        """
        Export public key to C header file for microcontrollers
        Args:
            output_path: Path to save .h file (default: keys/public_key.h)
            key_name: Name of the constant array in C code
        Returns: Path to generated file
        """
        if self.public_key is None:
            raise ValueError("Public key not loaded. Call load_keys() or generate_keypair() first.")
        
        if output_path is None:
            output_path = self.keys_dir / "public_key.h"
        else:
            output_path = Path(output_path)
        
        # Get raw key bytes (64 bytes without 0x04 prefix)
        key_bytes = self.export_public_key_raw()
        
        # Format as C array with proper indentation
        hex_values = []
        for i in range(0, len(key_bytes), 16):
            chunk = key_bytes[i:i+16]
            hex_line = "    " + ", ".join([f"0x{b:02X}" for b in chunk])
            hex_values.append(hex_line)
        
        # Join with actual newlines and comma
        key_array_content = ",\n".join(hex_values)
        
        # Generate header content
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        header_content = f"""/*
 * ============================================================================
 * ECDSA Public Key for Secure FOTA System
 * ============================================================================
 * Auto-generated by Secure FOTA Manager
 * Generated: {timestamp}
 * 
 * WARNING: DO NOT EDIT THIS FILE MANUALLY!
 * 
 * This file contains the ECDSA public key used to verify firmware signatures
 * before flashing to the target device (STM32 ECU).
 * ============================================================================
 */

#ifndef PUBLIC_KEY_H
#define PUBLIC_KEY_H

#include <stdint.h>

/*
 * ============================================================================
 * ECDSA Public Key Configuration
 * ============================================================================
 */

/* Elliptic Curve: SECP256R1 (NIST P-256) */
/* Key Format: Uncompressed point (X || Y coordinates) */
/* Key Size: 64 bytes (32 bytes X + 32 bytes Y) */
/* Hash Algorithm: SHA-256 */
/* Signature Algorithm: ECDSA */

/*
 * Public Key Array - Use this to verify firmware signatures
 * Format: Uncompressed (without 0x04 prefix)
 *   - First 32 bytes: X coordinate
 *   - Last 32 bytes: Y coordinate
 */
const uint8_t {key_name}[64] = {{
{",\\n".join(hex_values)}
}};

/*
 * ============================================================================
 * Usage Instructions for ESP32/STM32
 * ============================================================================
 * 
 * 1. Include this header in your firmware verification module:
 *    #include "public_key.h"
 * 
 * 2. Verify firmware signature using mbedtls or similar crypto library:
 * 
 *    Example with mbedtls (SECP256R1):
 *    ---------------------------------
 *    #include "mbedtls/ecdsa.h"
 *    #include "mbedtls/ecp.h"
 *    #include "mbedtls/sha256.h"
 * 
 *    // Step 1: Calculate SHA-256 hash of firmware
 *    uint8_t hash[32];
 *    mbedtls_sha256(firmware_data, firmware_size, hash, 0);
 * 
 *    // Step 2: Parse signature (r || s format, 64 bytes total)
 *    mbedtls_mpi r, s;
 *    mbedtls_mpi_init(&r);
 *    mbedtls_mpi_init(&s);
 *    mbedtls_mpi_read_binary(&r, signature, 32);      // First 32 bytes
 *    mbedtls_mpi_read_binary(&s, signature + 32, 32); // Last 32 bytes
 * 
 *    // Step 3: Load public key
 *    mbedtls_ecp_keypair keypair;
 *    mbedtls_ecp_keypair_init(&keypair);
 *    mbedtls_ecp_group_load(&keypair.grp, MBEDTLS_ECP_DP_SECP256R1);
 * 
 *    mbedtls_mpi_read_binary(&keypair.Q.X, {key_name}, 32);      // X coordinate
 *    mbedtls_mpi_read_binary(&keypair.Q.Y, {key_name} + 32, 32); // Y coordinate
 *    mbedtls_mpi_lset(&keypair.Q.Z, 1);
 * 
 *    // Step 4: Verify signature
 *    int ret = mbedtls_ecdsa_verify(&keypair.grp, hash, 32, 
 *                                   &keypair.Q, &r, &s);
 * 
 *    if (ret == 0) {{
 *        // ✅ Signature valid - Firmware is authentic
 *        printf("Signature verification SUCCESS\\n");
 *    }} else {{
 *        // ❌ Signature invalid - Reject firmware
 *        printf("Signature verification FAILED: %d\\n", ret);
 *    }}
 * 
 * 3. SECURITY NOTES:
 *    - Never expose or transmit the private key
 *    - This public key should be embedded in ESP32 Gateway firmware
 *    - Verify ALL firmware before flashing to STM32
 *    - Use secure boot and flash encryption on production devices
 * 
 * ============================================================================
 * Key Information
 * ============================================================================
 * Curve:              SECP256R1 (NIST P-256)
 * Key Type:           ECDSA Public Key
 * Key Size:           64 bytes (256 bits per coordinate)
 * Hash Algorithm:     SHA-256
 * Signature Size:     64 bytes (32 bytes r + 32 bytes s)
 * Compatible with:    ESP32, STM32, mbedtls, OpenSSL
 * Python Library:     cryptography (ec.SECP256R1)
 * mbedtls Curve ID:   MBEDTLS_ECP_DP_SECP256R1
 * ============================================================================
 */

#endif /* PUBLIC_KEY_H */
"""
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(header_content)
        
        return output_path
    
    def get_key_info(self):
        """
        Get information about loaded keys
        Returns: dict with key information
        """
        info = {
            "private_key_loaded": self.private_key is not None,
            "public_key_loaded": self.public_key is not None,
            "private_key_path": str(self.private_key_path) if self.private_key_path.exists() else None,
            "public_key_path": str(self.public_key_path) if self.public_key_path.exists() else None,
            "curve": "SECP256R1",
            "hash_algorithm": "SHA-256"
        }
        
        if self.public_key:
            info["public_key_hex"] = self.export_public_key_hex()
            
        return info


# Convenience functions
def generate_keys(keys_dir="keys"):
    """Generate and save ECDSA key pair"""
    crypto = CryptoManager(keys_dir)
    private_key, public_key = crypto.generate_keypair()
    private_path, public_path = crypto.save_keys()
    return crypto, private_path, public_path


def load_keys(keys_dir="keys"):
    """Load existing ECDSA keys"""
    crypto = CryptoManager(keys_dir)
    crypto.load_keys()
    return crypto


def sign_firmware(firmware_path, keys_dir="keys"):
    """Sign firmware file with private key"""
    crypto = load_keys(keys_dir)
    signature = crypto.sign_data(firmware_path)
    return signature


def verify_firmware(firmware_path, signature, keys_dir="keys"):
    """Verify firmware signature with public key"""
    crypto = load_keys(keys_dir)
    return crypto.verify_signature(firmware_path, signature)


if __name__ == "__main__":
    # Test the crypto module
    print("Testing Crypto Manager...")
    
    # Generate keys
    print("\n1. Generating ECDSA key pair...")
    crypto, priv_path, pub_path = generate_keys()
    print(f"   Private key: {priv_path}")
    print(f"   Public key: {pub_path}")
    
    # Get key info
    print("\n2. Key Information:")
    info = crypto.get_key_info()
    for key, value in info.items():
        if key == "public_key_hex":
            print(f"   {key}: {value[:64]}... (truncated)")
        else:
            print(f"   {key}: {value}")
    
    # Create test data
    print("\n3. Testing signing and verification...")
    test_data = b"This is test firmware data"
    
    # Sign
    signature = crypto.sign_data(test_data)
    print(f"   Signature length: {len(signature)} bytes")
    print(f"   Signature (hex): {signature.hex()[:64]}... (truncated)")
    
    # Verify
    is_valid = crypto.verify_signature(test_data, signature)
    print(f"   Verification result: {'VALID' if is_valid else 'INVALID'}")
    
    # Test with tampered data
    tampered_data = b"This is tampered firmware data"
    is_valid_tampered = crypto.verify_signature(tampered_data, signature)
    print(f"   Tampered data verification: {'VALID' if is_valid_tampered else 'INVALID (as expected)'}")
    
    print("\n✅ Crypto module test completed!")
