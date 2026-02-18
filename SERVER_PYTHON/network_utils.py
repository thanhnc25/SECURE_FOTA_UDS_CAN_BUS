#!/usr/bin/env python3
"""
Network Utilities for Secure FOTA Manager
Handles TCP server and client connections
"""

import socket
import threading
import time
from pathlib import Path
from protocol import FOTAProtocol


class UDPBeacon:
    """UDP Beacon for ESP32 Discovery"""
    
    def __init__(self, server_ip, server_port=8888, udp_port=2509, interval=2.0, callback=None):
        """
        Initialize UDP Beacon
        Args:
            server_ip: Server IP to broadcast
            server_port: TCP server port
            udp_port: UDP broadcast port (default 2509)
            interval: Broadcast interval in seconds
            callback: Optional callback function
        """
        self.server_ip = server_ip
        self.server_port = server_port
        self.broadcast_port = udp_port  # Internal variable name
        self.interval = interval
        self.callback = callback
        
        self.is_running = False
        self.broadcast_thread = None
        self.udp_socket = None
        
    def start(self):
        """Start UDP broadcasting"""
        if self.is_running:
            return
        
        try:
            # Create UDP socket
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            self.is_running = True
            
            # Start broadcast thread
            self.broadcast_thread = threading.Thread(target=self._broadcast_loop, daemon=True)
            self.broadcast_thread.start()
            
            if self.callback:
                self.callback('beacon_started', {
                    'server_ip': self.server_ip,
                    'server_port': self.server_port,
                    'broadcast_port': self.broadcast_port
                })
        except Exception as e:
            if self.callback:
                self.callback('beacon_error', {'message': str(e)})
            raise
    
    def _broadcast_loop(self):
        """Broadcast beacon messages"""
        while self.is_running:
            try:
                # Create beacon message: FOTA_BEACON|IP|PORT
                message = f"FOTA_BEACON|{self.server_ip}|{self.server_port}"
                
                # Send to broadcast address
                self.udp_socket.sendto(
                    message.encode('utf-8'),
                    ('<broadcast>', self.broadcast_port)
                )
                
                if self.callback:
                    self.callback('beacon_sent', {'message': message})
                
                # Wait before next broadcast
                time.sleep(self.interval)
                
            except Exception as e:
                if self.is_running and self.callback:
                    self.callback('beacon_error', {'message': str(e)})
                break
    
    def stop(self):
        """Stop UDP broadcasting"""
        self.is_running = False
        
        if self.udp_socket:
            try:
                self.udp_socket.close()
            except:
                pass
            self.udp_socket = None
        
        if self.broadcast_thread:
            self.broadcast_thread.join(timeout=3)
            self.broadcast_thread = None
        
        if self.callback:
            self.callback('beacon_stopped', {})
    
    def is_active(self):
        """Check if beacon is running"""
        return self.is_running


class TCPServer:
    """TCP Server for Gateway communication with UDP Discovery"""
    
    def __init__(self, host='0.0.0.0', port=8888, server_ip=None, callback=None):
        self.host = host
        self.port = port
        self.server_ip = server_ip  # IP to broadcast for discovery
        self.callback = callback
        
        self.server_socket = None
        self.client_socket = None
        self.client_address = None
        self.is_running = False
        self.accept_thread = None
        
        # UDP Beacon for discovery
        self.beacon = None
        
    def start(self, enable_beacon=True):
        """Start TCP server and optionally UDP beacon"""
        if self.is_running:
            raise RuntimeError("Server is already running")
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)
        
        self.is_running = True
        
        # Start accept thread
        self.accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.accept_thread.start()
        
        # Start UDP beacon if enabled and server_ip is set
        if enable_beacon and self.server_ip:
            try:
                self.beacon = UDPBeacon(
                    server_ip=self.server_ip,
                    server_port=self.port,
                    callback=self.callback
                )
                self.beacon.start()
            except Exception as e:
                if self.callback:
                    self.callback('error', {'message': f'Beacon failed: {str(e)}'})
        
        if self.callback:
            self.callback('server_started', {'host': self.host, 'port': self.port})
    
    def _accept_loop(self):
        """Accept incoming connections"""
        while self.is_running:
            try:
                client_socket, client_address = self.server_socket.accept()
                
                # Close previous client if exists
                if self.client_socket:
                    try:
                        self.client_socket.close()
                    except:
                        pass
                
                self.client_socket = client_socket
                self.client_address = client_address
                
                if self.callback:
                    self.callback('client_connected', {
                        'address': client_address[0],
                        'port': client_address[1]
                    })
                    
            except Exception as e:
                if self.is_running:
                    if self.callback:
                        self.callback('error', {'message': str(e)})
                break
    
    def stop(self):
        """Stop TCP server and UDP beacon"""
        self.is_running = False
        
        # Stop UDP beacon
        if self.beacon:
            try:
                self.beacon.stop()
            except:
                pass
            self.beacon = None
        
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
            self.client_socket = None
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None
        
        if self.callback:
            self.callback('server_stopped', {})
    
    def send_data(self, data):
        """Send data to connected client"""
        if not self.client_socket:
            raise ConnectionError("No client connected")
        
        try:
            self.client_socket.sendall(data)
            return True
        except Exception as e:
            if self.callback:
                self.callback('send_error', {'message': str(e)})
            return False
    
    def send_firmware_package(self, version, firmware_data, sha256_hash, ecdsa_signature, 
                             aes_iv=None, original_sha256=None, plaintext_signature=None, progress_callback=None):
        """
        Send firmware package to Gateway using FOTA Protocol with dual ECDSA signatures
        
        Args:
            version: Firmware version string
            firmware_data: Firmware binary data (encrypted if AES enabled)
            sha256_hash: 32-byte SHA-256 hash (of encrypted firmware)
            ecdsa_signature: 64-byte ECDSA signature (of encrypted firmware for OTA transport)
            aes_iv: 16-byte AES IV (optional, for AES-128-CBC)
            original_sha256: 32-byte SHA-256 hash of plaintext firmware (optional)
            plaintext_signature: 64-byte ECDSA signature of plaintext firmware for secure boot (optional)
            progress_callback: Optional callback for progress updates
        """
        if not self.client_socket:
            raise ConnectionError("No client connected")
        
        start_time = time.time()
        
        # Create FOTA protocol packet with AES IV
        if self.callback:
            self.callback('send_progress', {
                'stage': 'preparing',
                'message': 'Creating FOTA packet with AES support...'
            })
        
        packet = FOTAProtocol.create_packet(
            version,
            firmware_data,
            sha256_hash=sha256_hash,
            ecdsa_signature=ecdsa_signature,
            aes_iv=aes_iv,
            original_sha256=original_sha256,
            plaintext_signature=plaintext_signature
        )
        
        total_size = len(packet)
        header_size = FOTAProtocol.HEADER_SIZE
        firmware_size = len(firmware_data)
        
        if self.callback:
            self.callback('send_progress', {
                'stage': 'start',
                'total_size': total_size,
                'header_size': header_size,
                'firmware_size': firmware_size
            })
        
        # Send packet in chunks with progress tracking
        chunk_size = 4096
        sent = 0
        
        while sent < total_size:
            chunk = packet[sent:sent + chunk_size]
            self.client_socket.sendall(chunk)
            sent += len(chunk)
            
            # Calculate progress
            progress = (sent / total_size) * 100
            
            # Determine current stage
            if sent <= header_size:
                stage = 'header'
            elif sent <= header_size + firmware_size:
                stage = 'firmware'
            else:
                stage = 'complete'
            
            if self.callback:
                self.callback('send_progress', {
                    'stage': stage,
                    'sent': sent,
                    'total': total_size,
                    'progress': progress,
                    'speed': sent / (time.time() - start_time) if time.time() > start_time else 0
                })
            
            # Call optional progress callback
            if progress_callback:
                progress_callback(sent, total_size, progress)
        
        elapsed_time = time.time() - start_time
        avg_speed = total_size / elapsed_time if elapsed_time > 0 else 0
        
        if self.callback:
            self.callback('send_complete', {
                'total_size': total_size,
                'elapsed_time': elapsed_time,
                'avg_speed': avg_speed
            })
        
        return True
    
    def is_connected(self):
        """Check if client is connected"""
        return self.client_socket is not None and self.is_running
    
    def get_client_info(self):
        """Get connected client information"""
        if self.client_address:
            return {
                'address': self.client_address[0],
                'port': self.client_address[1],
                'connected': True
            }
        return {'connected': False}


# Convenience function
def create_server(port=8888, callback=None):
    """Create and return TCP server instance"""
    return TCPServer(host='0.0.0.0', port=port, callback=callback)
