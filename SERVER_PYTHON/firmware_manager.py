#!/usr/bin/env python3
"""
Firmware Manager for Secure FOTA Manager
Handles firmware version management, metadata, and update history
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List


class FirmwareManager:
    """Manage firmware files, versions, and metadata"""
    
    def __init__(self, firmware_dir="firmware", metadata_path="metadata.json"):
        self.firmware_dir = Path(firmware_dir)
        self.firmware_dir.mkdir(exist_ok=True)
        
        self.metadata_file = Path(metadata_path)
        self.metadata = self._load_metadata()
        
    def _load_metadata(self) -> dict:
        """Load metadata from JSON file"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading metadata: {e}")
                return self._create_default_metadata()
        return self._create_default_metadata()
    
    def _create_default_metadata(self) -> dict:
        """Create default metadata structure"""
        return {
            "project": {
                "name": "Secure FOTA Manager",
                "description": "Secure Firmware Over-The-Air Update System",
                "created_date": datetime.now().strftime("%Y-%m-%d"),
                "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            "firmware_versions": [],
            "security_config": {
                "signature_algorithm": "ECDSA",
                "hash_algorithm": "SHA-256",
                "key_curve": "SECP256K1",
                "public_key_file": "keys/public_key.pem",
                "private_key_file": "keys/private_key.pem"
            },
            "version_management": {
                "current_version": "",
                "min_supported_version": "",
                "auto_rollback": True,
                "verification_required": True
            },
            "update_history": []
        }
    
    def save_metadata(self):
        """Save metadata to JSON file"""
        self.metadata["project"]["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(self.metadata_file, 'w', encoding='utf-8') as f:
            json.dump(self.metadata, f, indent=2, ensure_ascii=False)
    
    def add_firmware(self, filepath: str, version: str, notes: str = "") -> dict:
        """
        Add new firmware to version management
        Args:
            filepath: Path to firmware file
            version: Version string (e.g., "1.0.0", "v1.2.3")
            notes: Release notes
        Returns:
            Firmware info dict
        """
        file_path = Path(filepath)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Firmware file not found: {filepath}")
        
        # Get file info
        file_size = file_path.stat().st_size
        filename = file_path.name
        
        # Check if version already exists
        for fw in self.metadata["firmware_versions"]:
            if fw["version"] == version:
                raise ValueError(f"Version {version} already exists")
        
        # Create firmware entry
        firmware_info = {
            "version": version,
            "release_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "filename": filename,
            "filepath": str(file_path),
            "size": file_size,
            "sha256_hash": "",
            "ecdsa_signature": "",
            "security_status": "pending",
            "target_device": "STM32",
            "build_number": len(self.metadata["firmware_versions"]) + 1,
            "notes": notes,
            "compressed": False,
            "compressed_size": 0
        }
        
        # Add to list
        self.metadata["firmware_versions"].append(firmware_info)
        
        # Update current version
        self.metadata["version_management"]["current_version"] = version
        
        # Save metadata
        self.save_metadata()
        
        return firmware_info
    
    def get_firmware_by_version(self, version: str) -> Optional[dict]:
        """Get firmware info by version"""
        for fw in self.metadata["firmware_versions"]:
            if fw["version"] == version:
                return fw
        return None
    
    def get_firmware_by_path(self, filepath: str) -> Optional[dict]:
        """Get firmware info by filepath"""
        filepath = str(Path(filepath))
        for fw in self.metadata["firmware_versions"]:
            if fw.get("filepath") == filepath or fw.get("filename") == Path(filepath).name:
                return fw
        return None
    
    def update_firmware_hash(self, version: str, sha256_hash: str):
        """Update SHA-256 hash for firmware version"""
        fw = self.get_firmware_by_version(version)
        if fw:
            fw["sha256_hash"] = sha256_hash
            self.save_metadata()
    
    def update_firmware_signature(self, version: str, signature_hex: str):
        """Update ECDSA signature for firmware version"""
        fw = self.get_firmware_by_version(version)
        if fw:
            fw["ecdsa_signature"] = signature_hex
            fw["security_status"] = "signed"
            self.save_metadata()
    
    def add_update_history(self, version: str, status: str, details: dict):
        """
        Add update history entry
        Args:
            version: Firmware version
            status: "success" or "failed"
            details: Additional information dict
        """
        history_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": version,
            "status": status,
            "gateway_ip": details.get("gateway_ip", ""),
            "transfer_time": details.get("transfer_time", 0),
            "bytes_sent": details.get("bytes_sent", 0),
            "sha256_enabled": details.get("sha256_enabled", False),
            "ecdsa_enabled": details.get("ecdsa_enabled", False),
            "error_message": details.get("error_message", ""),
            "notes": details.get("notes", "")
        }
        
        self.metadata["update_history"].append(history_entry)
        self.save_metadata()
    
    def get_update_history(self, limit: int = None) -> List[dict]:
        """
        Get update history
        Args:
            limit: Maximum number of entries to return (None = all)
        Returns:
            List of history entries (newest first)
        """
        history = self.metadata["update_history"]
        history.reverse()  # Newest first
        
        if limit:
            return history[:limit]
        return history
    
    def get_all_firmware_versions(self) -> List[dict]:
        """Get all firmware versions"""
        return self.metadata["firmware_versions"]
    
    def delete_firmware_version(self, version: str) -> bool:
        """Delete firmware version from metadata"""
        for i, fw in enumerate(self.metadata["firmware_versions"]):
            if fw["version"] == version:
                del self.metadata["firmware_versions"][i]
                self.save_metadata()
                return True
        return False
    
    def get_latest_version(self) -> Optional[dict]:
        """Get latest firmware version"""
        if self.metadata["firmware_versions"]:
            return self.metadata["firmware_versions"][-1]
        return None
    
    def validate_version_format(self, version: str) -> bool:
        """
        Validate version format
        Accepts: "1.0.0", "v1.0.0", "1.0", "v1.2.3-beta"
        """
        import re
        pattern = r'^v?\d+\.\d+(\.\d+)?(-[\w]+)?$'
        return bool(re.match(pattern, version))
    
    def compare_versions(self, version1: str, version2: str) -> int:
        """
        Compare two versions
        Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
        """
        # Remove 'v' prefix if exists
        v1 = version1.lstrip('v').split('-')[0]
        v2 = version2.lstrip('v').split('-')[0]
        
        # Split and compare
        parts1 = [int(x) for x in v1.split('.')]
        parts2 = [int(x) for x in v2.split('.')]
        
        # Pad shorter version with zeros
        max_len = max(len(parts1), len(parts2))
        parts1.extend([0] * (max_len - len(parts1)))
        parts2.extend([0] * (max_len - len(parts2)))
        
        for p1, p2 in zip(parts1, parts2):
            if p1 < p2:
                return -1
            elif p1 > p2:
                return 1
        
        return 0
    
    def get_statistics(self) -> dict:
        """Get firmware management statistics"""
        total_versions = len(self.metadata["firmware_versions"])
        total_updates = len(self.metadata["update_history"])
        
        successful_updates = sum(1 for h in self.metadata["update_history"] if h["status"] == "success")
        failed_updates = sum(1 for h in self.metadata["update_history"] if h["status"] == "failed")
        
        total_bytes_sent = sum(h.get("bytes_sent", 0) for h in self.metadata["update_history"])
        
        return {
            "total_versions": total_versions,
            "total_updates": total_updates,
            "successful_updates": successful_updates,
            "failed_updates": failed_updates,
            "success_rate": (successful_updates / total_updates * 100) if total_updates > 0 else 0,
            "total_bytes_sent": total_bytes_sent,
            "current_version": self.metadata["version_management"]["current_version"]
        }


# Convenience functions
def create_firmware_manager(firmware_dir="firmware", metadata_file="metadata.json"):
    """Create and return FirmwareManager instance"""
    return FirmwareManager(firmware_dir, metadata_file)


if __name__ == "__main__":
    # Test the firmware manager
    print("Testing Firmware Manager...")
    
    fm = FirmwareManager()
    
    print("\n1. Metadata loaded:")
    print(f"   Project: {fm.metadata['project']['name']}")
    print(f"   Total versions: {len(fm.metadata['firmware_versions'])}")
    print(f"   Total updates: {len(fm.metadata['update_history'])}")
    
    print("\n2. Statistics:")
    stats = fm.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n✅ Firmware Manager test completed!")
