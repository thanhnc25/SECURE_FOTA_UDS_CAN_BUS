#!/usr/bin/env python3
"""
Protocol definitions for Secure FOTA Manager
Defines packet structure and protocol handlers
"""

import struct
from typing import Tuple, Optional


class FOTAProtocol:
    """FOTA Protocol handler with custom header structure"""
    
    # Magic number for FOTA packets
    MAGIC_NUMBER = 0x41544F46  # 'FOTA' in ASCII
    
    # Protocol version
    PROTOCOL_VERSION = 0x0100  # v1.0
    
    # Flags
    FLAG_SHA256_ENABLED = 0x0001
    FLAG_ECDSA_ENABLED = 0x0002
    FLAG_COMPRESSED = 0x0004
    FLAG_ENCRYPTED = 0x0008  # AES-128 encryption enabled
    
    # Header structure (NEW with AES + Original SHA256 + Plaintext Signature for Secure Boot):
    # - Magic (4 bytes): 0x41544F46 ('FOTA')
    # - Version (12 bytes): ASCII string, null-terminated
    # - Firmware Size (4 bytes): Size of encrypted firmware data
    # - SHA256 Hash (32 bytes): Hash of encrypted firmware
    # - ECDSA Signature (64 bytes): Signature of encrypted (raw r||s)
    # - AES IV (16 bytes): AES-128-CBC Initialization Vector
    # - Original SHA256 (32 bytes): Hash of plaintext firmware (before encryption)
    # - Plaintext Signature (64 bytes): ECDSA signature of plaintext for secure boot (raw r||s)
    # Total: 228 bytes
    
    HEADER_FORMAT = '<I12sI32s64s16s32s64s'  # Little-endian
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 228 bytes
    
    @classmethod
    def create_header(cls,
                     version: str,
                     file_size: int,
                     sha256_hash: bytes,
                     ecdsa_signature: bytes,
                     aes_iv: bytes = None,
                     original_sha256: bytes = None,
                     plaintext_signature: bytes = None) -> bytes:
        """
        Create FOTA protocol header (228 bytes with dual ECDSA signatures for secure boot)
        
        Args:
            version: Version string (max 11 chars, will be null-terminated)
            file_size: Size of encrypted firmware data
            sha256_hash: 32-byte SHA-256 hash (of encrypted firmware)
            ecdsa_signature: 64-byte ECDSA signature of encrypted (raw r||s format)
            aes_iv: 16-byte AES Initialization Vector (if None, uses zeros)
            original_sha256: 32-byte SHA-256 hash of plaintext firmware (if None, uses zeros)
            plaintext_signature: 64-byte ECDSA signature of plaintext for secure boot (if None, uses zeros)
            
        Returns:
            228-byte header
        """
        # Ensure correct sizes
        if len(sha256_hash) != 32:
            raise ValueError(f"SHA-256 hash must be 32 bytes, got {len(sha256_hash)}")
        if len(ecdsa_signature) != 64:
            raise ValueError(f"ECDSA signature must be 64 bytes, got {len(ecdsa_signature)}")
        
        # If no AES IV provided, use zeros (for backward compatibility)
        if aes_iv is None:
            aes_iv = b'\x00' * 16
        elif len(aes_iv) != 16:
            raise ValueError(f"AES IV must be 16 bytes, got {len(aes_iv)}")
        
        # If no original SHA256 provided, use zeros (for plaintext firmware)
        if original_sha256 is None:
            original_sha256 = b'\x00' * 32
        elif len(original_sha256) != 32:
            raise ValueError(f"Original SHA-256 must be 32 bytes, got {len(original_sha256)}")
        
        # If no plaintext signature provided, use zeros (for backward compatibility)
        if plaintext_signature is None:
            plaintext_signature = b'\x00' * 64
        elif len(plaintext_signature) != 64:
            raise ValueError(f"Plaintext ECDSA signature must be 64 bytes, got {len(plaintext_signature)}")
        
        # Convert version string to 12-byte null-terminated buffer
        version_bytes = version.encode('ascii')[:11]  # Max 11 chars
        version_bytes = version_bytes.ljust(12, b'\x00')  # Pad to 12 bytes
        
        # Pack header
        header = struct.pack(
            cls.HEADER_FORMAT,
            cls.MAGIC_NUMBER,
            version_bytes,
            file_size,
            sha256_hash,
            ecdsa_signature,
            aes_iv,
            original_sha256,
            plaintext_signature
        )
        
        return header
    
    @classmethod
    def parse_header(cls, header_data: bytes) -> dict:
        """
        Parse FOTA protocol header (228 bytes with dual ECDSA signatures)
        
        Args:
            header_data: 228-byte header
            
        Returns:
            Dictionary with parsed fields
        """
        if len(header_data) != cls.HEADER_SIZE:
            raise ValueError(f"Invalid header size: {len(header_data)}, expected {cls.HEADER_SIZE}")
        
        # Unpack header
        magic, version_bytes, file_size, sha256_hash, ecdsa_signature, aes_iv, original_sha256, plaintext_signature = struct.unpack(
            cls.HEADER_FORMAT,
            header_data
        )
        
        # Verify magic number
        if magic != cls.MAGIC_NUMBER:
            raise ValueError(f"Invalid magic number: 0x{magic:08X}, expected 0x{cls.MAGIC_NUMBER:08X}")
        
        # Parse version string (remove null padding)
        version = version_bytes.rstrip(b'\x00').decode('ascii', errors='ignore')
        
        return {
            'magic': magic,
            'version': version,
            'file_size': file_size,
            'sha256_hash': sha256_hash,
            'ecdsa_signature': ecdsa_signature,
            'aes_iv': aes_iv,
            'original_sha256': original_sha256,
            'plaintext_signature': plaintext_signature
        }
    
    @classmethod
    def create_packet(cls,
                     version: str,
                     firmware_data: bytes,
                     sha256_hash: bytes,
                     ecdsa_signature: bytes,
                     aes_iv: bytes = None,
                     original_sha256: bytes = None,
                     plaintext_signature: bytes = None) -> bytes:
        """
        Create complete FOTA packet (header + encrypted firmware)
        
        Args:
            version: Firmware version string
            firmware_data: Firmware binary data (encrypted)
            sha256_hash: 32-byte SHA-256 hash (of encrypted firmware)
            ecdsa_signature: 64-byte ECDSA signature of encrypted
            aes_iv: 16-byte AES IV (optional)
            original_sha256: 32-byte SHA-256 hash of plaintext firmware (optional)
            plaintext_signature: 64-byte ECDSA signature of plaintext for secure boot (optional)
            
        Returns:
            Complete packet (header + encrypted firmware)
        """
        header = cls.create_header(
            version=version,
            file_size=len(firmware_data),
            sha256_hash=sha256_hash,
            ecdsa_signature=ecdsa_signature,
            aes_iv=aes_iv,
            original_sha256=original_sha256,
            plaintext_signature=plaintext_signature
        )
        
        return header + firmware_data
    
    @classmethod
    def parse_packet(cls, packet_data: bytes) -> Tuple[dict, bytes]:
        """
        Parse complete FOTA packet
        
        Args:
            packet_data: Complete packet data
            
        Returns:
            (header_dict, firmware_data)
        """
        if len(packet_data) < cls.HEADER_SIZE:
            raise ValueError(f"Packet too small: {len(packet_data)} bytes")
        
        header_data = packet_data[:cls.HEADER_SIZE]
        firmware_data = packet_data[cls.HEADER_SIZE:]
        
        header_info = cls.parse_header(header_data)
        
        # Verify firmware size
        if len(firmware_data) != header_info['file_size']:
            raise ValueError(
                f"Firmware size mismatch: got {len(firmware_data)}, "
                f"expected {header_info['file_size']}"
            )
        
        return header_info, firmware_data
    
    @classmethod
    def get_header_info_string(cls, header_dict: dict) -> str:
        """Get human-readable header information"""
        lines = []
        lines.append(f"Magic: 0x{header_dict['magic']:08X}")
        lines.append(f"Version: {header_dict['version'] >> 8}.{header_dict['version'] & 0xFF}")
        lines.append(f"Flags: 0x{header_dict['flags']:04X}")
        lines.append(f"  - SHA-256: {'Enabled' if header_dict['sha256_enabled'] else 'Disabled'}")
        lines.append(f"  - ECDSA: {'Enabled' if header_dict['ecdsa_enabled'] else 'Disabled'}")
        lines.append(f"  - Compressed: {'Yes' if header_dict['compressed'] else 'No'}")
        lines.append(f"File Size: {header_dict['file_size']} bytes")
        
        if header_dict['sha256_hash']:
            hash_hex = header_dict['sha256_hash'].hex()
            lines.append(f"SHA-256: {hash_hex[:32]}...")
        
        if header_dict['ecdsa_signature']:
            sig_hex = header_dict['ecdsa_signature'].hex()
            lines.append(f"Signature: {sig_hex[:32]}...")
        
        return '\n'.join(lines)


# Convenience functions
def create_fota_packet(firmware_data: bytes,
                      sha256_hash: bytes = None,
                      ecdsa_signature: bytes = None,
                      compressed: bool = False) -> bytes:
    """Create FOTA packet"""
    return FOTAProtocol.create_packet(firmware_data, sha256_hash, ecdsa_signature, compressed)


def parse_fota_packet(packet_data: bytes) -> Tuple[dict, bytes]:
    """Parse FOTA packet"""
    return FOTAProtocol.parse_packet(packet_data)


if __name__ == "__main__":
    # Test the protocol
    print("Testing FOTA Protocol...")
    
    # Create test data
    test_firmware = b"This is test firmware data" * 100
    test_hash = b'\xAB' * 32
    test_signature = b'\xCD' * 64
    
    print("\n1. Creating packet with full security...")
    packet = FOTAProtocol.create_packet(
        test_firmware,
        sha256_hash=test_hash,
        ecdsa_signature=test_signature,
        compressed=False
    )
    print(f"   Packet size: {len(packet)} bytes")
    print(f"   Header size: {FOTAProtocol.HEADER_SIZE} bytes")
    print(f"   Firmware size: {len(test_firmware)} bytes")
    
    print("\n2. Parsing packet...")
    header, firmware = FOTAProtocol.parse_packet(packet)
    print(FOTAProtocol.get_header_info_string(header))
    
    print("\n3. Creating packet without security...")
    packet_no_sec = FOTAProtocol.create_packet(test_firmware)
    header_no_sec, _ = FOTAProtocol.parse_packet(packet_no_sec)
    print(FOTAProtocol.get_header_info_string(header_no_sec))
    
    print("\n✅ Protocol test completed!")
